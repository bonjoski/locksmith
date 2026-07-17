# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "2.6.7"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v2.6.7/locksmith-darwin-arm64"
      sha256 "67512462aa1ee24009bf88debfecac3c629bed97e6246024e914dab1b0eb9004"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.6.7/summon-locksmith-darwin-arm64"
        sha256 "a44a6b03eddccc4b61bf727f56b3974ef58f1dc7ac0aa95a06d03774d036adb5"
      end

      def install
        bin.install "locksmith-darwin-arm64" => "locksmith"
        resource("summon-arm64").stage do
          bin.install "summon-locksmith-darwin-arm64" => "summon-locksmith"
        end
      end
    else
      url "https://github.com/bonjoski/locksmith/releases/download/v2.6.7/locksmith-darwin-amd64"
      sha256 "cdcd39e3bc4015a903e5314e3d8f534654314790d40c17a91944d2c19dd48e41"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.6.7/summon-locksmith-darwin-amd64"
        sha256 "2aa249542050d398b551a92818523be50362bf9572fb5f6a622824a0b6b11630"
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
