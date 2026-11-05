# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "3.2.3"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v3.2.3/locksmith-darwin-arm64"
      sha256 "a41d91cf17a51e6cbbd53a120e91297f556be61db99408de4962bc08b86abe29"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.3/summon-locksmith-darwin-arm64"
        sha256 "c74029e2047681fe5999809896a4bc76e7c5fc6c59370b5db5e171f4e6072bdf"
      end

      resource "git-credential-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.3/git-credential-locksmith-darwin-arm64"
        sha256 "73c4811c6dd6fe84c90e3c0dd11c2549bbff11947fc14cafa8c2a077d9a20c05"
      end

      resource "cockpit-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.3/locksmith-cockpit-darwin-arm64"
        sha256 "c76cf824479d95f2d6d4a8fbe80921a208fcd216c62b36fc47a73db5133fd179"
      end

      def install
        bin.install "locksmith-darwin-arm64" => "locksmith"
        resource("summon-arm64").stage do
          bin.install "summon-locksmith-darwin-arm64" => "summon-locksmith"
        end
        resource("git-credential-arm64").stage do
          bin.install "git-credential-locksmith-darwin-arm64" => "git-credential-locksmith"
        end
        resource("cockpit-arm64").stage do
          bin.install "locksmith-cockpit-darwin-arm64" => "locksmith-cockpit"
        end
      end
    else
      url "https://github.com/bonjoski/locksmith/releases/download/v3.2.3/locksmith-darwin-amd64"
      sha256 "bc98176600c728aa05ba69acbca89fac2b394d385e186c06ab29051a9d5a96b6"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.3/summon-locksmith-darwin-amd64"
        sha256 "1ca10fe355653be11707f0dcc92a3aac0bd7ad7f43deeaf704a9d81bcdd8c1fa"
      end

      resource "git-credential-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.3/git-credential-locksmith-darwin-amd64"
        sha256 "f6ea791b2e43cafecaccebc38259c6faa4ff083f07406bd230b3b2288f976549"
      end

      resource "cockpit-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.3/locksmith-cockpit-darwin-amd64"
        sha256 "d2e3dd53778d980b114b4bc0865bbfb5ca134d05040d360fb74b941cf631dd51"
      end

      def install
        bin.install "locksmith-darwin-amd64" => "locksmith"
        resource("summon-amd64").stage do
          bin.install "summon-locksmith-darwin-amd64" => "summon-locksmith"
        end
        resource("git-credential-amd64").stage do
          bin.install "git-credential-locksmith-darwin-amd64" => "git-credential-locksmith"
        end
        resource("cockpit-amd64").stage do
          bin.install "locksmith-cockpit-darwin-amd64" => "locksmith-cockpit"
        end
      end
    end
  end

  on_linux do
    url "https://github.com/bonjoski/locksmith/archive/refs/tags/v2.9.0.tar.gz"
    sha256 "164a576940ee1e3d8fb33e3737a55116cd6c8b6aa096c1acd9bd6400841e157e"

    depends_on "go" => :build

    def install
      system "go", "build", *std_go_args(ldflags: "-s -w"), "./cmd/locksmith"
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/locksmith --version 2>&1")
    assert_predicate bin/"locksmith-cockpit", :exist?
  end
end
