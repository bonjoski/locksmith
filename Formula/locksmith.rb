# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "2.2.5"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v2.2.5/locksmith-darwin-arm64"
      sha256 "REPLACE_WITH_ARM64_SHA256"

      def install
        bin.install "locksmith-darwin-arm64" => "locksmith"
      end
    else
      url "https://github.com/bonjoski/locksmith/releases/download/v2.2.5/locksmith-darwin-amd64"
      sha256 "REPLACE_WITH_AMD64_SHA256"

      def install
        bin.install "locksmith-darwin-amd64" => "locksmith"
      end
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/locksmith --version 2>&1")
  end
end
