// frontend/app/page.js (or any component)
"use client";
import { useState } from "react";

export default function Home() {
  const [response, setResponse] = useState("");

  const callFlask = async () => {
    const res = await fetch("http://localhost:5000/api/hello");
    const data = await res.json();
    setResponse(data.message);
  };

  return (
    <div className="p-4">
      <button 
        onClick={callFlask} 
        className="px-4 py-2 bg-blue-500 text-white rounded"
      >
        Call Flask
      </button>
      <p>Response: {response}</p>
    </div>
  );
}
