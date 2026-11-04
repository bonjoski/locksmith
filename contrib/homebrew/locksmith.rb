# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "3.2.2"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v3.2.2/locksmith-darwin-arm64"
      sha256 "d2f99644e0ba812da5bb5bc2911bbecc2e9f22b656f0d8b9e70edf8a1bcdddcc"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.2/summon-locksmith-darwin-arm64"
        sha256 "05ac0f9c76ced39f6f6aaaf5a7a097f1cadab5c5df6ef8f3c93fced4327c5909"
      end

      resource "git-credential-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.2/git-credential-locksmith-darwin-arm64"
        sha256 "90739a4dad9594a219815c1a3116666d5b784d4bf9640e1bd23f50e999509698"
      end

      resource "cockpit-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.2/locksmith-cockpit-darwin-arm64"
        sha256 "7b873e3b370117ce01255ece06d6fe3b7df58e766f12f7cd8e1a9e531be43222"
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
      url "https://github.com/bonjoski/locksmith/releases/download/v3.2.2/locksmith-darwin-amd64"
      sha256 "8ee36804ccfc30d048a84cea0d3db58b5e4a92f6dbe801b3db803919ea5b07f2"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.2/summon-locksmith-darwin-amd64"
        sha256 "a0e212b0de689858198a1d8d49d28e68d1402b6fa064547a3a8163f25cfd7b35"
      end

      resource "git-credential-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.2/git-credential-locksmith-darwin-amd64"
        sha256 "b20988d757b85313c19f34dbffa0d328ffe31617665380e56e951f883e2fec9d"
      end

      resource "cockpit-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.2/locksmith-cockpit-darwin-amd64"
        sha256 "266d5efa0ce3a22b22b2ee9e2aeec4f62d0039e6fb53376d8f037585d1dcd127"
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
