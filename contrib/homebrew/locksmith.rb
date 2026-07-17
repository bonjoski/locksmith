# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "2.6.5"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v2.6.5/locksmith-darwin-arm64"
      sha256 "a306a56a90a92384af876446fb1dfbc558b0c7a05916137edbd72389514a6f80"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.6.5/summon-locksmith-darwin-arm64"
        sha256 "04a2e08cc2369b63b95a19d4b9c9fa390a81cfd42dc86f250362405150417e9a"
      end

      def install
        bin.install "locksmith-darwin-arm64" => "locksmith"
        resource("summon-arm64").stage do
          bin.install "summon-locksmith-darwin-arm64" => "summon-locksmith"
        end
      end
    else
      url "https://github.com/bonjoski/locksmith/releases/download/v2.6.5/locksmith-darwin-amd64"
      sha256 "44bae6ba6eff1d3bc592541cdddbbbdc6305e46342eb29cf3facc38d943e3a27"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.6.5/summon-locksmith-darwin-amd64"
        sha256 "e439329860b8126ad9a46144961ce816af97a2b7c093132694ba9a6f5ce3ea77"
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
