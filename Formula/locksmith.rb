# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "2.4.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v2.4.0/locksmith-darwin-arm64"
      sha256 "b6c6d8fedad566b2c44d5995a2144a0a3c01df6299f7adc60a53b002b38b04e4"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.4.0/summon-locksmith-darwin-arm64"
        sha256 "52568f34bb0ad319fe7130ed6f39d9654bcd25073d5f63bcdf304446b96e0290"
      end

      def install
        bin.install "locksmith-darwin-arm64" => "locksmith"
        resource("summon-arm64").stage do
          bin.install "summon-locksmith-darwin-arm64" => "summon-locksmith"
        end
      end
    else
      url "https://github.com/bonjoski/locksmith/releases/download/v2.4.0/locksmith-darwin-amd64"
      sha256 "b6249baa6aeecf398c5caa9eb2730b7b46709795fd4c008eb6ba5b2d30618b35"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.4.0/summon-locksmith-darwin-amd64"
        sha256 "a91d2d7d5e475644200727af6dd585f170d12477ef75343f0d08cc4f6294068d"
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
