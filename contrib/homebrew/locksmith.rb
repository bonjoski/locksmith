# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "2.7.8"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v2.7.8/locksmith-darwin-arm64"
      sha256 "2c00c82c5b60c5c41aaf4b89c839497410314e1a4fa5b1651984dbf24728fa53"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.8/summon-locksmith-darwin-arm64"
        sha256 "a5065601587e4d1620d8ac7ac04be932f1469d3427750a42088104cbcdd754d5"
      end

      resource "git-credential-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.8/git-credential-locksmith-darwin-arm64"
        sha256 "16b16391ff167f45456abb9a28b2f61b470e758580c15969ae302a72e3a1b6da"
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
      url "https://github.com/bonjoski/locksmith/releases/download/v2.7.8/locksmith-darwin-amd64"
      sha256 "7cbf498c76c2f404fc8c5264dc97f86c84d762f1505c74d8cd289529f1c8515a"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.8/summon-locksmith-darwin-amd64"
        sha256 "bfda38663be3fa5e2b061d3c665fd43ce0d3c2e8b603b358ad4283d38a290708"
      end

      resource "git-credential-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.8/git-credential-locksmith-darwin-amd64"
        sha256 "ccf364d794442bc4963949fe333a67cb17aeddf70be5edd47aa8018acfee621b"
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
