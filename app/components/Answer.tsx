export function Answer({ answer }: { answer: string }) {
  return (
    <>
    <div className="flex flex-col h-full p-2 gap-2">
      <div>AI Response</div>
      <div id="answer" className="h-full overflow-scroll">
        {answer}
      </div>
      </div>
    </>
  );
}
