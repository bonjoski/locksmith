# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "3.2.1"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v3.2.1/locksmith-darwin-arm64"
      sha256 "b05166709e3c0dfd7a5b70b4e53dea7334354d18008494e847ec12b883dc849a"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.1/summon-locksmith-darwin-arm64"
        sha256 "40c766ead07ac2e33cd99f71ac2f5aeb09b7166769eb84b578a146b9ec85bf71"
      end

      resource "git-credential-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.1/git-credential-locksmith-darwin-arm64"
        sha256 "b03fc7950b8ccfcb0c01af1e3fd0768855db876374b94869e82a9f259df2d0d1"
      end

      resource "cockpit-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.1/locksmith-cockpit-darwin-arm64"
        sha256 "10f03619f6941a18a826e05ef6792b0928bb6ca74c0851e320d25cd47107f2f8"
      end

      def install
        bin.install "locksmith-darwin-arm64" => "locksmith"
        resource("summon-arm64").stage do
          bin.install "summon-locksmith-darwin-arm64" => "summon-locksmith"
        end
        resource("git-credential-arm64").stage do
          bin.install "git-credential-locksmith-darwin-arm64" => "git-credential-locksmith"
        end
        resource("cockpit-arm64").stage do
          bin.install "locksmith-cockpit-darwin-arm64" => "locksmith-cockpit"
        end
      end
    else
      url "https://github.com/bonjoski/locksmith/releases/download/v3.2.1/locksmith-darwin-amd64"
      sha256 "6a158228ea723a2344cc42243f1cec3b9cd1385b8c2d64834c895ad10c256b73"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.1/summon-locksmith-darwin-amd64"
        sha256 "29118ef7a6f269d2640f78e7c39e3e1d82b187521a7c4eabfe0a7d8720331663"
      end

      resource "git-credential-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.1/git-credential-locksmith-darwin-amd64"
        sha256 "8bc39ed4e50ed0c32695bcd034c6c3f860860b35006611d1c5058e37cc251b28"
      end

      resource "cockpit-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.1/locksmith-cockpit-darwin-amd64"
        sha256 "6090d334e6bd5799a157c402f5542b3af2a93cef8238b4017c202bc720ecc444"
      end

      def install
        bin.install "locksmith-darwin-amd64" => "locksmith"
        resource("summon-amd64").stage do
          bin.install "summon-locksmith-darwin-amd64" => "summon-locksmith"
        end
        resource("git-credential-amd64").stage do
          bin.install "git-credential-locksmith-darwin-amd64" => "git-credential-locksmith"
        end
        resource("cockpit-amd64").stage do
          bin.install "locksmith-cockpit-darwin-amd64" => "locksmith-cockpit"
        end
      end
    end
  end

  on_linux do
    url "https://github.com/bonjoski/locksmith/archive/refs/tags/v2.9.0.tar.gz"
    sha256 "164a576940ee1e3d8fb33e3737a55116cd6c8b6aa096c1acd9bd6400841e157e"

    depends_on "go" => :build

    def install
      system "go", "build", *std_go_args(ldflags: "-s -w"), "./cmd/locksmith"
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/locksmith --version 2>&1")
    assert_predicate bin/"locksmith-cockpit", :exist?
  end
end
