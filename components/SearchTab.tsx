'use client';

import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, Progress, Button } from './ui';
import { Search, Terminal, AlertTriangle } from 'lucide-react';

interface SearchResult {
  id: string;
  sessionId: string;
  chunkText: string;
  chunkIndex: number;
  lineStart: number;
  lineEnd: number;
  similarity: number;
}

interface SearchTabProps {
  sessionId: string;
}

export default function SearchTab({ sessionId }: SearchTabProps) {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<SearchResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId,
          query,
          limit: 10,
        }),
      });

      if (!res.ok) {
        throw new Error('Vector database semantic search query failed.');
      }

      const data = await res.json();
      setResults(data);
    } catch (err: any) {
      console.error('Semantic search error:', err);
      setError(err.message || 'An error occurred during log querying.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      
      {/* Semantic Search input portal */}
      <Card className="border-slate-800 bg-slate-900/40">
        <CardContent className="pt-6">
          <form onSubmit={handleSearch} className="flex gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-md pl-10 pr-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-red-500 font-mono"
                placeholder="Enter search keywords or conceptual queries (e.g. 'root authentication bypass')..."
              />
            </div>
            <Button type="submit" loading={loading} className="glow-red font-mono text-xs uppercase px-5">
              SEARCH VECTOR INDEX
            </Button>
          </form>

          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-xs rounded-md mt-4 font-mono flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              <span>{error}</span>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Matching log chunks results */}
      <div className="space-y-4">
        {loading ? (
          <div className="py-12 flex flex-col items-center justify-center space-y-4">
            <div className="h-8 w-8 border-4 border-red-500 border-t-transparent rounded-full animate-spin" />
            <p className="text-xs font-mono text-slate-500 uppercase tracking-widest animate-pulse">
              COMPUTING LOG SEMANTIC SIMILARITY...
            </p>
          </div>
        ) : results.length === 0 ? (
          <div className="text-center py-16 border border-dashed border-slate-800 rounded-lg">
            <Terminal className="h-10 w-10 text-slate-700 mx-auto mb-4" />
            <h3 className="text-slate-400 font-semibold font-mono text-sm uppercase">No Vector Matches Found</h3>
            <p className="text-slate-600 text-xs mt-1">
              Enter a search query above to query logs by semantic intent.
            </p>
          </div>
        ) : (
          results.map((result) => {
            const similarityPercent = Math.round(result.similarity * 100);

            return (
              <Card key={result.id} className="border-slate-800/80 bg-slate-900/10 hover:border-slate-800 transition-colors">
                
                {/* Result header details */}
                <CardHeader className="bg-slate-950/40 pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-xs font-mono text-red-400 flex items-center gap-2">
                      <Terminal className="h-3 w-3 text-red-500" />
                      <span>MATCHED LOG ENTRY (similarity: {(result.similarity * 100).toFixed(1)}%)</span>
                    </CardTitle>
                    <CardDescription className="text-slate-500 font-mono text-[10px] mt-0.5">
                      CHUNK INDEX: #{result.chunkIndex}
                    </CardDescription>
                  </div>

                  {/* Similarity Progress */}
                  <div className="flex items-center gap-3 w-full sm:w-48 mt-2 sm:mt-0">
                    <span className="text-xs font-mono text-slate-400 font-semibold">{similarityPercent}% Match</span>
                    <Progress value={similarityPercent} className="h-1.5 flex-1" />
                  </div>
                </CardHeader>

                {/* Raw log text */}
                <CardContent className="pt-2">
                  <div className="bg-slate-950/80 p-4 border border-slate-800 rounded font-mono text-[10px] text-slate-400 overflow-x-auto whitespace-pre space-y-1">
                    {result.chunkText.split('\n').map((line, idx) => (
                      <div key={idx} className="hover:bg-slate-900/40 px-2 py-0.5 rounded transition-colors">
                        <span className="text-slate-600 select-none mr-3">[{result.lineStart + idx}]</span>
                        {line}
                      </div>
                    ))}
                  </div>
                </CardContent>

              </Card>
            );
          })
        )}
      </div>

    </div>
  );
}
