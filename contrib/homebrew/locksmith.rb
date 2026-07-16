# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "2.6.4"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v2.6.4/locksmith-darwin-arm64"
      sha256 "a099114f49e71f2581dde845cae42258783286667de7e7d12f73ddb37b2140ea"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.6.4/summon-locksmith-darwin-arm64"
        sha256 "961251b132b60292364399dde60fe023de224ee929fae168ce01bf8cc6ebd7d6"
      end

      def install
        bin.install "locksmith-darwin-arm64" => "locksmith"
        resource("summon-arm64").stage do
          bin.install "summon-locksmith-darwin-arm64" => "summon-locksmith"
        end
      end
    else
      url "https://github.com/bonjoski/locksmith/releases/download/v2.6.4/locksmith-darwin-amd64"
      sha256 "2953b2b3821d128b919b0b29d0db8d5d29bf884964936b686f16476776ec823f"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.6.4/summon-locksmith-darwin-amd64"
        sha256 "b400842d5b1be812ef798fa952ba957c8576778327ccbc604275815f8b1e26ba"
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
