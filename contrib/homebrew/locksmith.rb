# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "2.7.4"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v2.7.4/locksmith-darwin-arm64"
      sha256 "872b6d690a704a0141249a1d1201071359bbead95bf66d63d838686d7482c3e1"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.4/summon-locksmith-darwin-arm64"
        sha256 "210c9e45b88be6ee9aecefd90452b456ed68a79df8e8afc7768f367af5e25a12"
      end

      def install
        bin.install "locksmith-darwin-arm64" => "locksmith"
        resource("summon-arm64").stage do
          bin.install "summon-locksmith-darwin-arm64" => "summon-locksmith"
        end
      end
    else
      url "https://github.com/bonjoski/locksmith/releases/download/v2.7.4/locksmith-darwin-amd64"
      sha256 "1550b40aec187725ea79e3752c372d14381c6b70aa82979cb27cc140ca64914d"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.4/summon-locksmith-darwin-amd64"
        sha256 "628a7b3a545a281fcdd71e396b2f6f291e1f6d32b995c682bedc1756777b7bc5"
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
