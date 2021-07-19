import $ivy.`com.lihaoyi::mill-contrib-bloop:$MILL_VERSION`
import $ivy.`io.get-coursier::coursier-launcher:2.0.16`
import $file.project.deps, deps.{Deps, Scala}
import $file.project.ghreleaseassets
import $file.project.publish, publish.ScalaCliPublishModule
import $file.project.settings, settings.{CliLaunchers, FormatNativeImageConf, HasTests, LocalRepo, PublishLocalNoFluff, localRepoResourcePath}

import java.io.File

import de.tobiasroeser.mill.vcs.version.VcsVersion
import mill._, scalalib.{publish => _, _}
import mill.contrib.bloop.Bloop

import _root_.scala.util.Properties


// Tell mill modules are under modules/
implicit def millModuleBasePath: define.BasePath =
  define.BasePath(super.millModuleBasePath.value / "modules")


object cli                    extends Cli
object `cli-core`             extends CliCore
object build                  extends Cross[Build]             (defaultScalaVersion)
object stubs                  extends JavaModule with ScalaCliPublishModule with PublishLocalNoFluff
object runner                 extends Cross[Runner]            (Scala.all: _*)
object `test-runner`          extends Cross[TestRunner]        (Scala.all: _*)
object `bloop-rifle`          extends Cross[BloopRifle]        (Scala.allScala2: _*)
object `tasty-lib`            extends Cross[TastyLib]          (Scala.all: _*)

object `integration-core` extends Module {
  object jvm    extends JvmIntegrationCore {
    object test extends Tests
  }
  object native extends NativeIntegrationCore with Bloop.Module {
    def skipBloop = true
    object test extends Tests with Bloop.Module {
      def skipBloop = true
    }
  }
}

object integration extends Module {
  object jvm    extends JvmIntegration {
    object test extends Tests {
      def sources = T.sources {
        super.sources() ++ `integration-core`.jvm.test.sources()
      }
    }
  }
  object native extends NativeIntegration with Bloop.Module {
    def skipBloop = true
    object test extends Tests with Bloop.Module {
      def skipBloop = true
      def sources = T.sources {
        super.sources() ++ `integration-core`.native.test.sources()
      }
    }
  }
}

object packager extends ScalaModule with Bloop.Module {
  def skipBloop = true
  def scalaVersion = Scala.scala213
  def ivyDeps = Agg(
    Deps.scalaPackagerCli
  )
  def mainClass = Some("cli.PackagerCli")
}

object `generate-reference-doc` extends SbtModule {
  def scalaVersion = defaultScalaVersion
  def moduleDeps = Seq(
    cli
  )
  def ivyDeps = Agg(
    Deps.caseApp,
    Deps.munit
  )
  def mainClass = Some("scala.cli.doc.GenerateReferenceDoc")
}

object dummy extends Module {
  // dummy project to get scala steward updates for Ammonite, whose
  // version is used in the repl command, and ensure Ammonite is available
  // for all Scala versions we support
  object amm extends Cross[Amm](Scala.listAll: _*)
  class Amm(val crossScalaVersion: String) extends CrossScalaModule with Bloop.Module {
    def skipBloop = true
    def ivyDeps = Agg(
      Deps.ammonite
    )
  }
}


// We should be able to switch to 2.13.x when bumping the scala-native version
def defaultScalaVersion = Scala.scala212

class Build(val crossScalaVersion: String) extends CrossSbtModule with ScalaCliPublishModule with HasTests {
  def moduleDeps = Seq(
    `bloop-rifle`(),
    `test-runner`(),
    `tasty-lib`()
  )
  def ivyDeps = super.ivyDeps() ++ Agg(
    Deps.asm,
    Deps.bloopConfig,
    Deps.coursierJvm
      // scalaJsEnvNodeJs brings a guava version that conflicts with this
      .exclude(("com.google.collections", "google-collections")),
    Deps.dependency,
    Deps.guava, // for coursierJvm / scalaJsEnvNodeJs, see above
    Deps.nativeTestRunner,
    Deps.nativeTools,
    Deps.osLib,
    Deps.pprint,
    Deps.pureconfig,
    Deps.scalaJsEnvNodeJs,
    Deps.scalaJsLinkerInterface,
    Deps.scalaJsTestAdapter,
    Deps.scalametaTrees,
    Deps.scalaparse,
    Deps.swoval
  )

  private def vcsState = {
    val isCI = System.getenv("CI") != null
    if (isCI)
      T.persistent {
        VcsVersion.vcsState()
      }
    else
      T {
        VcsVersion.vcsState()
      }
  }
  def constantsFile = T{
    val dest = T.dest / "Constants.scala"
    val code =
      s"""package scala.build.internal
         |
         |/** Build-time constants. Generated by mill. */
         |object Constants {
         |  def version = "${publishVersion()}"
         |  def detailedVersion = "${vcsState().format()}"
         |
         |  def scalaJsVersion = "${Deps.scalaJsLinker.dep.version}"
         |  def scalaNativeVersion = "${Deps.nativeTools.dep.version}"
         |
         |  def stubsOrganization = "${stubs.pomSettings().organization}"
         |  def stubsModuleName = "${stubs.artifactName()}"
         |  def stubsVersion = "${stubs.publishVersion()}"
         |
         |  def testRunnerOrganization = "${`test-runner`(defaultScalaVersion).pomSettings().organization}"
         |  def testRunnerModuleName = "${`test-runner`(defaultScalaVersion).artifactName()}"
         |  def testRunnerVersion = "${`test-runner`(defaultScalaVersion).publishVersion()}"
         |  def testRunnerMainClass = "${`test-runner`(defaultScalaVersion).mainClass().getOrElse(sys.error("No main class defined for test-runner"))}"
         |
         |  def runnerOrganization = "${runner(defaultScalaVersion).pomSettings().organization}"
         |  def runnerModuleName = "${runner(defaultScalaVersion).artifactName()}"
         |  def runnerVersion = "${runner(defaultScalaVersion).publishVersion()}"
         |  def runnerMainClass = "${runner(defaultScalaVersion).mainClass().getOrElse(sys.error("No main class defined for runner"))}"
         |
         |  def semanticDbPluginOrganization = "${Deps.scalametaTrees.dep.module.organization.value}"
         |  def semanticDbPluginModuleName = "semanticdb-scalac"
         |  def semanticDbPluginVersion = "${Deps.scalametaTrees.dep.version}"
         |
         |  def localRepoResourcePath = "$localRepoResourcePath"
         |  def localRepoVersion = "${vcsState().format()}"
         |
         |  def jmhVersion = "1.29"
         |
         |  def ammoniteVersion = "${Deps.ammonite.dep.version}"
         |}
         |""".stripMargin
    os.write(dest, code)
    PathRef(dest)
  }
  def generatedSources = super.generatedSources() ++ Seq(constantsFile())

  def localRepoJar = T{
    `local-repo`.localRepoJar()
  }

  object test extends Tests {
    def ivyDeps = super.ivyDeps() ++ Agg(
      Deps.pprint
    )
    def runClasspath = T{
      super.runClasspath() ++ Seq(localRepoJar())
    }
  }
}

trait Cli extends SbtModule with CliLaunchers with ScalaCliPublishModule with FormatNativeImageConf with HasTests {
  def scalaVersion = defaultScalaVersion
  def moduleDeps = Seq(
    `cli-core`
  )
  def ivyDeps = super.ivyDeps() ++ Agg(
    Deps.metabrowseServer,
    Deps.slf4jNop
  )
  def compileIvyDeps = super.compileIvyDeps() ++ Agg(
    Deps.svm
  )
  def mainClass = Some("scala.cli.ScalaCli")

  def localRepoJar = `local-repo`.localRepoJar()
  def graalVmVersion = deps.graalVmVersion

  // lsp4j, pulled by metabrowse, brings a class that conflicts with one
  // defined in bloop, and sometimes creates issues when running
  // native-image
  def stripLsp4jPreconditionsFromBsp4j = true

  object test extends Tests
}

trait CliCore extends SbtModule with CliLaunchers with ScalaCliPublishModule with FormatNativeImageConf {
  def scalaVersion = defaultScalaVersion
  def moduleDeps = Seq(
    build(defaultScalaVersion),
    `test-runner`(defaultScalaVersion)
  )
  def ivyDeps = super.ivyDeps() ++ Agg(
    Deps.caseApp,
    Deps.coursierLauncher,
    Deps.jimfs, // scalaJsEnvNodeJs pulls jimfs:1.1, whose class path seems borked (bin compat issue with the guava version it depends on)
    Deps.jniUtils,
    Deps.scalaJsLinker,
    Deps.scalaPackager,
    Deps.svmSubs
  )
  def compileIvyDeps = super.compileIvyDeps() ++ Agg(
    Deps.svm
  )
  def mainClass = Some("scala.cli.ScalaCliCore")

  def localRepoJar = `local-repo`.localRepoJar()
  def graalVmVersion = deps.graalVmVersion
}

trait CliIntegrationBase extends SbtModule with ScalaCliPublishModule with HasTests {
  def scalaVersion = sv
  def testLauncher: T[PathRef]
  def isNative = T{ false }

  def sv = Scala.scala213

  def prefix: String

  private def mainArtifactName = T{ artifactName() }
  trait Tests extends super.Tests {
    def ivyDeps = super.ivyDeps() ++ Agg(
      Deps.bsp4j,
      Deps.osLib,
      Deps.pprint,
      Deps.scalaAsync
    )
    def forkEnv = super.forkEnv() ++ Seq(
      "SCALA_CLI" -> testLauncher().path.toString,
      "IS_NATIVE_SCALA_CLI" -> isNative().toString
    )
    def sources = T.sources {
      val name = mainArtifactName().stripPrefix(prefix)
      super.sources().map { ref =>
        PathRef(os.Path(ref.path.toString.replace(File.separator + name + File.separator, File.separator)))
      }
    }

    def constantsFile = T{
      val dest = T.dest / "Constants.scala"
      val code =
        s"""package scala.cli.integration
           |
           |/** Build-time constants. Generated by mill. */
           |object Constants {
           |  def bspVersion = "${Deps.bsp4j.dep.version}"
           |}
           |""".stripMargin
      os.write(dest, code)
      PathRef(dest)
    }
    def generatedSources = super.generatedSources() ++ Seq(constantsFile())
  }
}

trait CliIntegration extends CliIntegrationBase {
  def prefix = "integration-"
}

trait CliIntegrationCore extends CliIntegration {
  def prefix = "integration-core-"
}

trait NativeIntegration extends CliIntegration {
  def testLauncher = cli.nativeImage()
  def isNative = true
}

trait JvmIntegration extends CliIntegration {
  def testLauncher = cli.launcher()
}

trait NativeIntegrationCore extends CliIntegrationCore {
  def testLauncher = `cli-core`.nativeImage()
  def isNative = true
}

trait JvmIntegrationCore extends CliIntegrationCore {
  def testLauncher = `cli-core`.launcher()
}

class Runner(val crossScalaVersion: String) extends CrossSbtModule with ScalaCliPublishModule with PublishLocalNoFluff {
  def mainClass = Some("scala.cli.runner.Runner")
  def ivyDeps =
    if (crossScalaVersion.startsWith("3.") && !crossScalaVersion.contains("-RC"))
      Agg(Deps.prettyStacktraces)
    else
      Agg.empty[Dep]
  def repositories = super.repositories ++ Seq(
    coursier.Repositories.sonatype("snapshots")
  )
  def sources = T.sources {
    val scala3DirNames =
      if (crossScalaVersion.startsWith("3.")) {
        val name =
          if (crossScalaVersion.contains("-RC")) "scala-3-unstable"
          else "scala-3-stable"
        Seq(name)
      } else Nil
    val extraDirs = scala3DirNames.map(name => PathRef(millSourcePath / "src" / "main" / name))
    super.sources() ++ extraDirs
  }
}

class TestRunner(val crossScalaVersion: String) extends CrossSbtModule with ScalaCliPublishModule with PublishLocalNoFluff {
  def ivyDeps = super.ivyDeps() ++ Agg(
    Deps.asm,
    Deps.testInterface
  )
  def mainClass = Some("scala.cli.testrunner.DynamicTestRunner")
}

class BloopRifle(val crossScalaVersion: String) extends CrossSbtModule with ScalaCliPublishModule {
  def ivyDeps = super.ivyDeps() ++ Agg(
    Deps.bsp4j,
    Deps.ipcSocket,
    Deps.snailgun
  )
  def mainClass = Some("scala.build.blooprifle.BloopRifle")

  def constantsFile = T{
    val dest = T.dest / "Constants.scala"
    val code =
      s"""package scala.build.blooprifle.internal
         |
         |/** Build-time constants. Generated by mill. */
         |object Constants {
         |  def bloopVersion = "${Deps.bloopConfig.dep.version}"
         |  def bspVersion = "${Deps.bsp4j.dep.version}"
         |}
         |""".stripMargin
    os.write(dest, code)
    PathRef(dest)
  }
  def generatedSources = super.generatedSources() ++ Seq(constantsFile())
}

class TastyLib(val crossScalaVersion: String) extends CrossSbtModule with ScalaCliPublishModule

object `local-repo` extends LocalRepo {
  def stubsModules = {
    val javaModules = Seq(
      stubs
    )
    val crossModules = for {
      sv <- Scala.all
      proj <- Seq(runner, `test-runner`)
    } yield proj(sv)
    javaModules ++ crossModules
  }
  def version = runner(defaultScalaVersion).publishVersion()
}


// Helper CI commands

def publishSonatype(tasks: mill.main.Tasks[PublishModule.PublishData]) = T.command {
  publish.publishSonatype(
    data = define.Task.sequence(tasks.value)(),
    log = T.ctx().log
  )
}

def copyTo(task: mill.main.Tasks[PathRef], dest: os.Path) = T.command {
  if (task.value.length > 1)
    sys.error("Expected a single task")
  val ref = task.value.head()
  os.makeDir.all(dest / os.up)
  os.copy.over(ref.path, dest)
}


def copyLauncher(directory: String = "artifacts") = T.command {
  val nativeLauncher = cli.nativeImage().path
  ghreleaseassets.copyLauncher(nativeLauncher, directory)
}

def copyCoreLauncher(directory: String = "artifacts") = T.command {
  val nativeLauncher = `cli-core`.nativeImage().path
  ghreleaseassets.copyLauncher(nativeLauncher, directory)
}

def uploadLaunchers(directory: String = "artifacts") = T.command {
  val version = cli.publishVersion()
  ghreleaseassets.uploadLaunchers(version, directory)
}

def unitTests() = T.command {
  build(defaultScalaVersion).test.test()()
  cli.test.test()()
}

def scala(args: String*) = T.command {
  cli.run(args: _*)()
}
