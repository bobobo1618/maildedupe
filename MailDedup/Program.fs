open System.Security.Cryptography

let utf8 (string: string) = System.Text.Encoding.UTF8.GetBytes(string)

type MessageKey =
    | CleanKey of cleanKey: byte[]
    | DirtyKey of dirtyKey: byte[]

let cleanlyHashedMessageId (message: MimeKit.MimeMessage): byte[] =
    let messageId = 
        try message.MessageId with
        | _ -> message.Headers.["Message-ID"]
    let date = message.Headers.["Date"]
    SHA256.HashData(utf8 $"{messageId}-{date}-{message.Subject}") 
let badlyHashedMessageId (message: MimeKit.MimeMessage): byte[] =
    SHA256.HashData(utf8 $"{message.Date}-${message.Subject}")

let messageKey (message: MimeKit.MimeMessage): MessageKey =
    try message |> cleanlyHashedMessageId |> CleanKey with
    | _ -> message |> badlyHashedMessageId |> DirtyKey

type PotentialDupe =
    struct
        val path: string
        val key: MessageKey
        val numHeaders: int
        val date: System.DateTimeOffset

        new (path: string, message: MimeKit.MimeMessage) = {
            path = path
            key = messageKey message
            numHeaders = Seq.length message.Headers
            date = message.Date
        }
    end

let handleMbox (path: string) =
    let inputStream = System.IO.File.Open(path, System.IO.FileMode.Open)
    let parser = MimeKit.MimeParser(inputStream, MimeKit.MimeFormat.Mbox)    
    let result =
        seq { while not parser.IsEndOfStream do parser.ParseMessage() }
        |> Seq.map (fun m -> PotentialDupe (path, m))
    inputStream.Close()
    result

let readPotentialDupe(path: string): Async<PotentialDupe> =
    async {
        let! inputStream = System.IO.File.ReadAllBytesAsync(path) |> Async.AwaitTask
        let result =
            inputStream
            |> fun m -> new System.IO.MemoryStream(m)
            |> MimeKit.MimeParser
            |> fun m -> m.ParseMessage()
            |> fun m -> PotentialDupe(path, m)
        return result
    }

type Group = 
    struct
        val key: MessageKey
        val dupes: seq<PotentialDupe>
        
        new (key: MessageKey, dupes: seq<PotentialDupe>) = {
            key = key
            dupes = dupes
        }
    end

type GroupResult = 
    struct
        val key: MessageKey
        val dupes: seq<PotentialDupe>
        val keep: seq<PotentialDupe>
        
        new (key: MessageKey, dupes, keep: seq<PotentialDupe>) = {
            key = key
            dupes = dupes
            keep = keep
        }
    end

let handleGroup (group: Group) =

    let minHeaders = group.dupes |> Seq.map(fun (dupe) -> dupe.numHeaders) |> Seq.min

    let dupeIs (dupe: PotentialDupe, what: string) =
        dupe.path.Contains what

    let keep =
        group.dupes
        |> Seq.filter(fun (dupe) -> dupe.numHeaders <= minHeaders)

    let has (stuff: seq<PotentialDupe>, what: string) =
        stuff
        |> Seq.map (fun dupe -> dupeIs (dupe, what))
        |> Seq.reduce (fun acc x -> acc || x)

    let hasArchive = has(keep, "Archive")
    let hasSent = has(keep, "Sent")

    let keep =
        if hasSent then
            keep |> Seq.filter (fun dupe -> dupeIs (dupe, "Sent"))
        elif hasArchive then
            keep |> Seq.filter (fun dupe -> dupeIs (dupe, "Archive"))
        else keep

    let keep = Seq.head keep

    let dupes = group.dupes |> Seq.except [keep]
    GroupResult(group.key, dupes, [keep])

let formatDupes(dupes: seq<PotentialDupe>) =
    dupes
    |> Seq.map(fun dupe -> $"{dupe.path}: {dupe.numHeaders}")
    |> String.concat("\n\t\t")

let printResult(result: GroupResult) =
    let dupesString = formatDupes result.dupes
    let keepString = formatDupes result.keep
    let keyValue =
        match result.key with
        | CleanKey(cleanKey) -> cleanKey
        | DirtyKey(dirtyKey) -> dirtyKey
    let keyType =
        match result.key with
        | CleanKey(_) -> "clean"
        | DirtyKey(_) -> "dirty"
    let hexString = keyValue |> Array.fold (fun state x-> state + sprintf "%02X" x) ""
    printfn "%s:%s:\n\tDupes:\n\t\t%s\n\tKeep:\n\t\t%s" keyType hexString dupesString keepString

let resultSummary(groupResult: seq<GroupResult>): int * int =
    groupResult
    |> Seq.map(fun result -> (Seq.length result.dupes, Seq.length result.keep))
    |> Seq.reduce (fun (accDupes, accKeeps) (newDupes, newKeeps) -> (accDupes + newDupes, accKeeps + newKeeps))

let keySummary(groupResult: seq<GroupResult>): int * int =
    groupResult
    |> Seq.map(fun result -> 
        match result.key with
        | CleanKey(_) -> (1, 0)
        | _ -> (0, 1)
    )
    |> Seq.reduce (fun (x1, y1) (x2, y2) -> (x1 + x2, y1 + y2))

[<EntryPoint>]
let main args =
    let maildirPath = Seq.last args

    printfn "Traversing files..."
    let fileNames =
        System.IO.Directory.EnumerateFiles(maildirPath, "*", System.IO.SearchOption.AllDirectories)
        |> Seq.toList
    let numFiles = Seq.length fileNames
    printfn "Found %d files" numFiles

    let fileProgressBar = new ShellProgressBar.ProgressBar(numFiles, "Processing files...")
    let groupResult =
        fileNames
        |> Seq.map (fun f -> async {
            let! result = readPotentialDupe(f)
            fileProgressBar.Tick()
            return result
        })
        |> Async.Parallel
        |> Async.RunSynchronously
        |> Seq.groupBy(fun dupe -> dupe.key)
        |> Seq.map Group
        |> Seq.sortBy(fun (group) -> Seq.length group.dupes)
        |> Seq.map handleGroup
        |> Seq.toList
    fileProgressBar.Dispose()

    groupResult |> Seq.iter printResult
    groupResult
    |> resultSummary
    |> fun s -> printfn "Total emails: %d, total dupes: %d, total unique: %d" (fst s + snd s) (fst s) (snd s)

    groupResult
    |> keySummary
    |> fun (clean, dirty) -> printfn "Total keys: %d dirty, %d clean" dirty clean

    printfn "Delete dupes?"
    if System.Console.ReadKey().Key.Equals(System.ConsoleKey.Y) then
        printfn "\nDeleting."
        let dupeFileNames =
            groupResult
            |> Seq.map (fun g -> g.dupes)
            |> Seq.concat
            |> Seq.map (fun d -> d.path)
        let deleteProgressBar = new ShellProgressBar.ProgressBar(Seq.length dupeFileNames, "Deleting...")
        dupeFileNames
        |> Seq.iter (fun path ->
            System.IO.File.Delete path
            deleteProgressBar.Tick()
        )
        deleteProgressBar.Dispose()
    

    printfn "\nDone"
    0
