# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "2.7.5"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v2.7.5/locksmith-darwin-arm64"
      sha256 "5b19d51e96dec829a4b1e011064ea76fe2e4399af3fe42f282380b352e758661"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.5/summon-locksmith-darwin-arm64"
        sha256 "6968eea12cd97bf0739587c5fccab34339941086f97cb59476c0de979fc53dad"
      end

      def install
        bin.install "locksmith-darwin-arm64" => "locksmith"
        resource("summon-arm64").stage do
          bin.install "summon-locksmith-darwin-arm64" => "summon-locksmith"
        end
      end
    else
      url "https://github.com/bonjoski/locksmith/releases/download/v2.7.5/locksmith-darwin-amd64"
      sha256 "0defbdf01ef24bd25d3dd10af1ee78a487b1c9819284c62e11e3784fb8d97eaa"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.5/summon-locksmith-darwin-amd64"
        sha256 "f6f431deca84f5aed328550208abe3a33a1cc1dafe8a327811ac0fc6caf7f9ef"
      end

      def install
        bin.install "locksmith-darwin-amd64" => "locksmith"
        resource("summon-amd64").stage do
          bin.install "summon-locksmith-darwin-amd64" => "summon-locksmith"
        end
      end
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/locksmith --version 2>&1")
    assert_match version.to_s, shell_output("#{bin}/summon-locksmith --version 2>&1")
  end
end
