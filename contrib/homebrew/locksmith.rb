# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "3.0.1"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v3.0.1/locksmith-darwin-arm64"
      sha256 "e6eddee4567514b0952be3d0e7c4372bf6241b83d8b3fd8190fecc2bb828fa15"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.0.1/summon-locksmith-darwin-arm64"
        sha256 "9e6f1934e1c73a0c2f2b76f6b1d4fb6de01669cfeb26b29bbe544a30fd02adf4"
      end

      resource "git-credential-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.0.1/git-credential-locksmith-darwin-arm64"
        sha256 "5dfea3f56acd1bea336f0245c03405fafaf88c8d196527f9358272b905785f0e"
      end

      resource "cockpit-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.0.1/locksmith-cockpit-darwin-arm64"
        sha256 "0000000000000000000000000000000000000000000000000000000000000000"
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
      url "https://github.com/bonjoski/locksmith/releases/download/v3.0.1/locksmith-darwin-amd64"
      sha256 "2fc82ab0eea5e95ace72baa217cf797659b54aa51a57f247c437e0badcfd8275"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.0.1/summon-locksmith-darwin-amd64"
        sha256 "e588793b9cc2d5049e86be3a4ec2d6fbaf60ddda44bce309df2f789cd5a2409c"
      end

      resource "git-credential-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.0.1/git-credential-locksmith-darwin-amd64"
        sha256 "36038fa52420de918d024af0e2525fb6efcff6bf8e65340edea21758ce694b97"
      end

      resource "cockpit-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.0.1/locksmith-cockpit-darwin-amd64"
        sha256 "0000000000000000000000000000000000000000000000000000000000000000"
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
