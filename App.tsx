import React from 'react';
import DockerTerminal from './components/DockerTerminal';

function App() {
  return (
    <div className="min-h-screen bg-gray-900 text-white flex flex-col items-center justify-start p-4 font-sans">
      <header className="w-full max-w-7xl mx-auto text-center my-6">
        <h1 className="text-4xl font-bold text-cyan-400 flex items-center justify-center gap-3">
          <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-cyan-500"><path d="M22 18V6H2l10 12L22 6V4H2v2l10 12L22 4h-2.31"/><path d="M14 12.37V6.03h-2.11v1.16l2.11 2.37zM2 18v-2h20v2Z"/><path d="M4.69 16l-2.31-2.63"/><path d="M19.31 16l2.31-2.63"/></svg>
          Real Docker Terminal
        </h1>
        <p className="text-gray-400 mt-2">
          This component now uses a backend service to execute <span className="font-bold text-cyan-300">real</span> Docker commands on the host machine.
        </p>
         <div className="mt-4 p-3 bg-gray-800 border border-yellow-500 rounded-lg text-sm text-yellow-300">
            <strong>Important:</strong> To run this application, you must also start the backend server. Navigate to the `server` directory, run `npm install`, and then `npm start`. Ensure Docker is running on your system.
        </div>
      </header>
      <main className="w-full flex-grow">
        <DockerTerminal />
      </main>
    </div>
  );
}

export default App;