# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "2.7.6"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v2.7.6/locksmith-darwin-arm64"
      sha256 "461117160100d5a2470cecb3055a6c7abf11b06f384a268c0ac52843446f9729"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.6/summon-locksmith-darwin-arm64"
        sha256 "d058760b36e619f50c1e94546f5653136f3f04ae16c39dbc5c0ee9321f7e17ea"
      end

      def install
        bin.install "locksmith-darwin-arm64" => "locksmith"
        resource("summon-arm64").stage do
          bin.install "summon-locksmith-darwin-arm64" => "summon-locksmith"
        end
      end
    else
      url "https://github.com/bonjoski/locksmith/releases/download/v2.7.6/locksmith-darwin-amd64"
      sha256 "950dc78e8489e37ade82cd7db90f284c952d97fe55c7b722669cea60a94b2771"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v2.7.6/summon-locksmith-darwin-amd64"
        sha256 "1ca43ca509b83065d98dbc3aea9bcd7c1feebd6285372d93effc7436dde70a1d"
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
