# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "2.6.6"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v2.6.6/locksmith-darwin-arm64"
      sha256 "cfc111b983e19f1c6420effef79f4b991a02d1485ba3592448614197c1c6555e"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.6.6/summon-locksmith-darwin-arm64"
        sha256 "7bbd18b4e40b4772b23cee89cc3cb1873b5bb4a463fc3ecd35797b2404e83332"
      end

      def install
        bin.install "locksmith-darwin-arm64" => "locksmith"
        resource("summon-arm64").stage do
          bin.install "summon-locksmith-darwin-arm64" => "summon-locksmith"
        end
      end
    else
      url "https://github.com/bonjoski/locksmith/releases/download/v2.6.6/locksmith-darwin-amd64"
      sha256 "a5b3ee1d56b476badad97440f28f32aca54e12394e77e9bbc9f0adbc4534fdae"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.6.6/summon-locksmith-darwin-amd64"
        sha256 "feb349d211e3a73385c3c006350b43395c2b25ce93d4bdd23d36408504e9ea46"
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
