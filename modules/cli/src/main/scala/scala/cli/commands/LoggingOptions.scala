package scala.cli.commands

import caseapp._
import upickle.default.{ReadWriter => RW, _}

import scala.build.Logger
import scala.cli.internal.CliLogger

// format: off
final case class LoggingOptions(
  @Recurse
    verbosityOptions: VerbosityOptions = VerbosityOptions(),
  @Group("Logging")
  @HelpMessage("Decrease verbosity")
  @Name("q")
    quiet: Boolean = false,
  @Group("Logging")
  @HelpMessage("Use progress bars")
    progress: Option[Boolean] = None
) {
  // format: on

  lazy val verbosity = verbosityOptions.verbosity - (if (quiet) 1 else 0)

  lazy val logger: Logger =
    new CliLogger(verbosity, quiet, progress, System.err)

}

object LoggingOptions {
  lazy val parser: Parser[LoggingOptions]                           = Parser.derive
  implicit lazy val parserAux: Parser.Aux[LoggingOptions, parser.D] = parser
  implicit lazy val help: Help[LoggingOptions]                      = Help.derive
  implicit val rw: RW[LoggingOptions]                               = macroRW
}
