defmodule PEST.Mixfile do
  use Mix.Project

  def project do
    [app: :pest,
     version: "0.9.0",
     language: :erlang,
     description: description(),
     package: package(),
     deps: deps()]
  end

  def application do
    [applications: [
       :syntax_tools]]
  end

  defp deps do
    []
  end

  defp description do
    "Primitive Erlang Security Tool"
  end

  defp package do
    [files: ~w(pest.erl src doc priv rebar.config README.markdown LICENSE),
     maintainers: ["Michael Truog"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/okeuday/pest"}]
   end
end
