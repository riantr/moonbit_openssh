///| The JSON payloads the command bridge exchanges with the page

///|

///| Every shape here is read off `proton_contract`'s and `proton/command`'s

///| `pkg.generated.mbti`, not from a README:
///

///|     pub fn[Request, Response] command(String)

///|         -> Command[Request, Response]                    // proton_contract

///|     pub fn[Request : @json.FromJson, Response : ToJson]

///|         CommandRegistrar::bind(Self, Command[Request, Response],

///|             async (CommandContext, Request) -> Response) -> Unit raise

///|                                                        // proton/command

///|

///| So a request type needs `FromJson` and a response type needs `ToJson`,

///| and the handler is async and takes the request context first. The context

///| is unused here: these scenarios are pure computation over bytes, with no

///| window and no permission scope, and the naming is kept so the shape

///| matches every other Proton command rather than being a special case.
///

///| A command registered through an application registrar is transported as

///| `app:<name>` (`ContractRoute::operation_name`), and the injected bridge

///| exposes exactly that as `window.__MoonBit__.app.<name>(payload)`

///| (`bridge_bootstrap.js`: one property per granted op). The page therefore

///| calls `__MoonBit__.app.sftp_fault_run({name: ...})` -- no transport name

///| is assembled by hand, which is the point of the grant-per-op design.

///|
/// `{"name": "<scenario>"}`
pub(all) struct RunRequest {
  name : String
} derive(ToJson, FromJson, Debug, Eq)

///|
/// What one scenario produced, rendered as text for the panel.
pub(all) struct RunReply {
  name : String
  intent : String
  /// true when the transcript matched the oracle
  pass : Bool
  done : Bool
  failed : Bool
  /// `SftpSession::failure_reason`, empty when it did not fail
  reason : String
  version : Int
  extensions : Int
  /// the extension names VERSION listed, in the order it listed them
  ext_names : Array[String]
  /// the requests we emitted, as hex
  requests : Array[String]
  /// one rendered line per result
  results : Array[String]
  /// the mismatches; empty when `pass`
  failures : Array[String]
} derive(ToJson, Debug, Eq)

///|
/// The catalogue the page renders its buttons from.
pub(all) struct ListReply {
  scenarios : Array[String]
  /// scenario name -> what it is aimed at
  intents : Array[String]
} derive(ToJson, Debug, Eq)

///|
/// The whole-suite verdict, so the page can show a single line.
pub(all) struct AllReply {
  total : Int
  passed : Int
  failures : Array[String]
  notes : Array[String]
} derive(ToJson, Debug, Eq)

///|
pub fn reply_of(
  name : String,
  intent : String,
  pass : Bool,
  r : Run,
  failures : Array[String],
) -> RunReply {
  RunReply::{
    name,
    intent,
    pass,
    done: r.done,
    failed: r.failed,
    reason: r.reason,
    version: r.version,
    extensions: r.extensions,
    ext_names: r.ext_names,
    requests: r.requests,
    results: r.results,
    failures,
  }
}
