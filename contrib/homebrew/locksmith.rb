# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "2.7.3"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v2.7.3/locksmith-darwin-arm64"
      sha256 "c0a90d4bb05b92bd088f5f3528d6f7772d6e25cc81ac076eb4c86bda960a8055"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.3/summon-locksmith-darwin-arm64"
        sha256 "932bed8906d2e6220850dc53c6c4e9fb06acd5c844cd46fc117e9028bfefe5f6"
      end

      def install
        bin.install "locksmith-darwin-arm64" => "locksmith"
        resource("summon-arm64").stage do
          bin.install "summon-locksmith-darwin-arm64" => "summon-locksmith"
        end
      end
    else
      url "https://github.com/bonjoski/locksmith/releases/download/v2.7.3/locksmith-darwin-amd64"
      sha256 "ce40dda91bd9d9c1d252b53a93ac7b2af92e5c6408a3c31e0ce94abf6b325fa1"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.3/summon-locksmith-darwin-amd64"
        sha256 "1d6757e9123b311040a8148cfb57f9ce66c0b3a15b07f23b117eb59ce4ec13ff"
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
