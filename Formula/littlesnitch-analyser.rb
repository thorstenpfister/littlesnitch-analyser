class LittlesnitchAnalyser < Formula
  desc "Filter and aggregate Little Snitch log-traffic CSV into JSON"
  homepage "https://github.com/thorstenpfister/littlesnitch-analyser"
  url "https://github.com/thorstenpfister/littlesnitch-analyser/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "2daf29eeb1898504ed98faf911d66f6edfaf133fb87f0556f2181edae277706e"
  license "MIT"
  head "https://github.com/thorstenpfister/littlesnitch-analyser.git", branch: "main"

  depends_on "go" => :build

  def install
    ldflags = %W[-s -w -X main.version=#{version}]
    system "go", "build", *std_go_args(ldflags: ldflags), "./cmd/littlesnitch-analyser"
  end

  test do
    assert_match "littlesnitch-analyser #{version}", shell_output("#{bin}/littlesnitch-analyser --version")
  end
end
