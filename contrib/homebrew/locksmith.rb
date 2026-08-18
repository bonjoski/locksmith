# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "2.7.7"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v2.7.7/locksmith-darwin-arm64"
      sha256 "710bbacf3868c05e59054cc7748c6dced1436d45afc649bafb567db61db17bd8"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.7/summon-locksmith-darwin-arm64"
        sha256 "5e51750ea566d11197002e128dfdc2725f7f316688e523b20bec15126f684e68"
      end

      def install
        bin.install "locksmith-darwin-arm64" => "locksmith"
        resource("summon-arm64").stage do
          bin.install "summon-locksmith-darwin-arm64" => "summon-locksmith"
        end
      end
    else
      url "https://github.com/bonjoski/locksmith/releases/download/v2.7.7/locksmith-darwin-amd64"
      sha256 "471a8afedd25049991cf0d138ca6e980d2cdc34f17ca2de303585d7d5b0581b4"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.7/summon-locksmith-darwin-amd64"
        sha256 "b53a2e81d99682bb8aa6e04b910d99200335009c3c6774adcc725a75d89c799d"
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
