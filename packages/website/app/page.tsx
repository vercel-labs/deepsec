import { Button } from "@vercel/geistdocs/components/button";
import Link from "next/link";
import { RunCommand } from "@/components/run-command";

const docsUrl = "/docs";

const points = [
  "Modern AI models are great at security code review.",
  "Most review solutions only run on pull requests.",
  "That means most legacy code was never reviewed, and your code from 6 months ago was reviewed by older models.",
  "Instead deepsec does security review on ALL of your existing code using scaled VM fanout.",
  "Vercel's deepsec is open source, runs in your own infrastructure, and supports strong agent sandboxing.",
];

export default function Home() {
  return (
    <div className="min-h-screen bg-background-100 text-gray-1000">
      <main>
        <section className="mx-auto flex w-full max-w-2xl flex-col px-4 pb-24 pt-24 sm:px-6 sm:pt-32">
          <h1 className="text-5xl font-semibold leading-none sm:text-6xl">deepsec</h1>
          <ul className="mt-10 flex flex-col gap-4 text-lg leading-8 text-gray-900">
            {points.map((point) => (
              <li key={point} className="flex gap-3">
                <span aria-hidden className="shrink-0 select-none text-gray-700">
                  —
                </span>
                <span>{point}</span>
              </li>
            ))}
          </ul>
          <div className="mt-10 flex flex-col gap-3">
            <RunCommand command="npx deepsec init" />
            <div className="flex flex-col items-stretch gap-3 sm:flex-row sm:items-center">
              <Button asChild className="w-full shadow-none sm:w-auto" size="lg" variant="outline">
                <Link href={docsUrl}>Read the full docs</Link>
              </Button>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
