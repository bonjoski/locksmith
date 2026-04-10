# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "2.2.6"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v2.2.5/locksmith-darwin-arm64"
      sha256 "a67f4fc4445c15ae8a4d52207c2d11af32bcb31b5a6cb19c24986cf60c919860"

      def install
        bin.install "locksmith-darwin-arm64" => "locksmith"
      end
    else
      url "https://github.com/bonjoski/locksmith/releases/download/v2.2.5/locksmith-darwin-amd64"
      sha256 "8d1744e46ad8b185d82173515297279862995cf1a9488afc10197524bfd49fea"

      def install
        bin.install "locksmith-darwin-amd64" => "locksmith"
      end
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/locksmith --version 2>&1")
  end
end
