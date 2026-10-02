# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "2.7.15"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v2.7.15/locksmith-darwin-arm64"
      sha256 "2f629030157cb8fb1f60fa63c052b0da2422975c0ead69d19c29fdf13b71a806"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.15/summon-locksmith-darwin-arm64"
        sha256 "7c2647b6331fcdc75cab55a39d6a4e5066e81c2395ac259d7c1ff11c9419f597"
      end

      resource "git-credential-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.15/git-credential-locksmith-darwin-arm64"
        sha256 "b107bf7013d6c9970ad08e862423b56d519d134a0bec1e7a569175269994175b"
      end

      def install
        bin.install "locksmith-darwin-arm64" => "locksmith"
        resource("summon-arm64").stage do
          bin.install "summon-locksmith-darwin-arm64" => "summon-locksmith"
        end
        resource("git-credential-arm64").stage do
          bin.install "git-credential-locksmith-darwin-arm64" => "git-credential-locksmith"
        end
      end
    else
      url "https://github.com/bonjoski/locksmith/releases/download/v2.7.15/locksmith-darwin-amd64"
      sha256 "502e5d574abe397d48ae8f329fbc2fea5df16776cc9e3e93e734c88af284e87d"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.15/summon-locksmith-darwin-amd64"
        sha256 "09bb595f3a7b58ce2e7e2995ed6d5eeaffb3913a080e95fab9498dd6382897e6"
      end

      resource "git-credential-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.15/git-credential-locksmith-darwin-amd64"
        sha256 "490171a8e6d659dc4f5f9a4270eaa384bee9c19fcd2cffe82a7d9517c18aeede"
      end

      def install
        bin.install "locksmith-darwin-amd64" => "locksmith"
        resource("summon-amd64").stage do
          bin.install "summon-locksmith-darwin-amd64" => "summon-locksmith"
        end
        resource("git-credential-amd64").stage do
          bin.install "git-credential-locksmith-darwin-amd64" => "git-credential-locksmith"
        end
      end
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/locksmith --version 2>&1")
    assert_match version.to_s, shell_output("#{bin}/summon-locksmith --version 2>&1")
    assert_match version.to_s, shell_output("#{bin}/git-credential-locksmith --version 2>&1")
  end
end
