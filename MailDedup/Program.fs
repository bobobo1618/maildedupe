open System.Security.Cryptography

//let mboxPath = "/Users/lucas/ProtonBackup"
//let mboxes = System.IO.Directory.GetFiles(mboxPath)

let utf8 (string: string) = System.Text.Encoding.UTF8.GetBytes(string)

let cleanlyHashedMessageId (message: MimeKit.MimeMessage): byte[] =
    let messageId = 
        try message.MessageId with
        | _ -> message.Headers["Message-ID"]
    let date = message.Headers["Date"]
    SHA256.HashData(utf8 $"{messageId}-{date}-{message.Subject}") 
let badlyHashedMessageId (message: MimeKit.MimeMessage): byte[] =
    SHA256.HashData(utf8 $"{message.Date}-${message.Subject}")

let messageKey (message: MimeKit.MimeMessage): byte[] =
    try cleanlyHashedMessageId message with
    | _ -> badlyHashedMessageId message

type PotentialDupe =
    struct
        val path: string
        val key: byte[]
        val isProton: bool
        val numHeaders: int
        val date: System.DateTimeOffset

        new (path: string, message: MimeKit.MimeMessage) = {
            path = path
            key = messageKey message
            isProton = message.Headers.Contains "X-Pm-Origin"
            numHeaders = Seq.length message.Headers
            date = message.Date
        }
    end

let handleMbox (path: string) =
    let inputStream = System.IO.File.Open(path, System.IO.FileMode.Open)
    let parser = MimeKit.MimeParser(inputStream, MimeKit.MimeFormat.Mbox)
    let messageStream =
        seq { while not parser.IsEndOfStream do parser.ParseMessage() }
    seq {for message in messageStream do PotentialDupe(path, message)}
    inputStream.Close()

let readPotentialDupe(path: string): PotentialDupe =
    let inputStream = System.IO.File.OpenRead(path)
    let result =
        inputStream
        |> MimeKit.MimeParser
        |> fun m -> m.ParseMessage()
        |> fun m -> PotentialDupe(path, m)
    inputStream.Close()
    result

type Group = 
    struct
        val key: byte[]
        val dupes: seq<PotentialDupe>
        
        new (key: byte[], dupes: seq<PotentialDupe>) = {
            key = key
            dupes = dupes
        }
    end

type GroupResult = 
    struct
        val key: byte[]
        val dupes: seq<PotentialDupe>
        val keep: seq<PotentialDupe>
        
        new (key: byte[], dupes, keep: seq<PotentialDupe>) = {
            key = key
            dupes = dupes
            keep = keep
        }
    end

let handleGroup (group: Group) =
    let keep =
        try
        group.dupes |> Seq.find(fun (dupe) -> not dupe.isProton) |> ignore
        group.dupes |> Seq.filter(fun (dupe) -> not dupe.isProton)
        with
        | _ -> group.dupes

    let minHeaders = keep |> Seq.map(fun (dupe) -> dupe.numHeaders) |> Seq.min
    let keep = keep |> Seq.filter(fun (dupe) -> dupe.numHeaders <= minHeaders)
    let minDate = keep |> Seq.map(fun (dupe) -> dupe.date) |> Seq.min
    let keep = keep |> Seq.filter(fun (dupe) -> dupe.date <= minDate) 

    let dupes = group.dupes |> Seq.except keep
    GroupResult(group.key, dupes, keep)

let formatDupes(dupes: seq<PotentialDupe>) =
    dupes
    |> Seq.map(fun dupe -> $"{dupe.path}: {dupe.isProton}, {dupe.numHeaders}")
    |> String.concat("\n\t\t")

let printResult(result: GroupResult) =
    let dupesString = formatDupes result.dupes
    let keepString = formatDupes result.keep
    let hexString = result.key |> Array.fold (fun state x-> state + sprintf "%02X" x) ""
    printfn "%s:\n\tDupes:\n\t\t%s\n\tKeep:\n\t\t%s" hexString dupesString keepString

System.IO.Directory.EnumerateFiles("/home/lucas/commail", "*", System.IO.SearchOption.AllDirectories)
|> Seq.map readPotentialDupe
|> Seq.groupBy(fun dupe -> dupe.key)
|> Seq.iter(fun ((k, v): byte[] * seq<PotentialDupe>) -> Group(k, v))
|> Seq.sortBy(fun (group) -> Seq.length group.dupes)
|> Seq.iter handleGroup
|> Seq.iter printResult

printfn "Done"
