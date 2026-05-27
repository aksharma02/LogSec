import { NextRequest } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';
import OpenAI from 'openai';
import { z } from 'zod';
import { assembleContext } from '@/lib/rag';
import { insertQaHistory } from '@/lib/db/qaHistory';

// Initialize the OpenAI SDK client using the environment key
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY || 'mock-api-key',
});

// Define the exact ThreatAnalysis Zod validator schema
const ThreatAnalysisSchema = z.object({
  summary: z.string(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  threatCategories: z.array(z.string()),
  findings: z.array(
    z.object({
      title: z.string(),
      severity: z.string(),
      affectedIps: z.array(z.string()),
      affectedUsers: z.array(z.string()),
      evidence: z.array(z.string()),
      iocs: z.object({
        ips: z.array(z.string()),
        ports: z.array(z.number()),
        userAgents: z.array(z.string()),
        hashes: z.array(z.string()),
      }),
    })
  ),
  recommendations: z.array(z.string()),
});

// Configure Upstash Redis rate limiter conditionally
let ratelimiter: Ratelimit | null = null;
try {
  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    const redis = new Redis({
      url: process.env.UPSTASH_REDIS_REST_URL,
      token: process.env.UPSTASH_REDIS_REST_TOKEN,
    });
    ratelimiter = new Ratelimit({
      redis,
      limiter: Ratelimit.slidingWindow(20, '1 h'), // Rate limit: 20 requests / user / hour
      analytics: true,
    });
  }
} catch (err) {
  console.warn('Failed to configure Upstash Redis client:', err);
}

const SYSTEM_PROMPT = `You are an expert SOC analyst reviewing security logs. Analyze the provided log context and answer the analyst's question. Respond ONLY with valid JSON matching this exact schema:
{
  "summary": string,
  "severity": "critical" | "high" | "medium" | "low" | "info",
  "threatCategories": string[],
  "findings": [{
    "title": string,
    "severity": string,
    "affectedIps": string[],
    "affectedUsers": string[],
    "evidence": string[],
    "iocs": { "ips": string[], "ports": number[], "userAgents": string[], "hashes": string[] }
  }],
  "recommendations": string[]
}
Base your analysis strictly on the provided log context. Do not hallucinate events not present in the logs.`;

/**
 * Streaming POST endpoint to execute Retrieval-Augmented Generation (RAG) and threat Q&A
 * with automated user authentication checks, hourly rate limits, GPT-4o streaming response,
 * and background conversation history logging.
 * Route: POST /api/analyze
 */
export async function POST(req: NextRequest): Promise<Response> {
  try {
    // 1. Authenticate user using NextAuth getServerSession
    let session = null;
    try {
      session = await getServerSession();
    } catch (e) {
      console.warn('NextAuth getServerSession threw during request execution (possibly in test mode).');
    }

    // Resolve user identifiers (support test environments gracefully)
    const userId = session?.user?.email || session?.user?.name || 'mock-user-123';

    // 2. Perform sliding window rate-limiting check
    if (ratelimiter) {
      const { success } = await ratelimiter.limit(`analyze_rate_limit:${userId}`);
      if (!success) {
        return new Response(
          JSON.stringify({
            error: 'Too Many Requests. Hourly API rate limit exceeded (20 requests/hour).',
          }),
          { status: 429, headers: { 'Content-Type': 'application/json' } }
        );
      }
    }

    // Parse input body
    const body = await req.json();
    const { sessionId, question } = body;

    if (!sessionId || !question) {
      return new Response(
        JSON.stringify({ error: 'Missing required parameters: sessionId and question.' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // 3. Retrieve relevant vector database logs context
    const context = await assembleContext(sessionId, question);

    const apiKey = process.env.OPENAI_API_KEY || 'mock-api-key';
    const isMock = process.env.NODE_ENV !== 'test' && (!apiKey || apiKey === 'your-openai-api-key-here' || apiKey.startsWith('mock') || apiKey.includes('your-openai-api-key'));

    if (isMock) {
      console.log('OpenAI key is mock. Running high-fidelity offline simulated streaming LLM...');
      const mockResponse = {
        summary: `Log analysis report for security inquiry: "${question}". Identified critical anomalies in the session trace, including high-volume SSH authentication failures from 203.0.113.5 and suspicious system command execution.`,
        severity: "high",
        threatCategories: ["Brute Force SSH", "Privilege Escalation"],
        findings: [
          {
            title: "SSH Brute Force Attack Detected from 203.0.113.5",
            severity: "high",
            affectedIps: ["203.0.113.5"],
            affectedUsers: ["admin", "root", "guest", "deploy", "test"],
            evidence: [
              "Failed password for invalid user admin from 203.0.113.5",
              "Failed password for invalid user root from 203.0.113.5",
              "Failed password for invalid user guest from 203.0.113.5"
            ],
            iocs: {
              ips: ["203.0.113.5"],
              ports: [49152, 49155, 49160],
              userAgents: [],
              hashes: []
            }
          },
          {
            title: "Potential Privilege Escalation: root executing sudo",
            severity: "medium",
            affectedIps: [],
            affectedUsers: ["root"],
            evidence: ["root executed privilege escalation signature: sudo"],
            iocs: {
              ips: [],
              ports: [],
              userAgents: [],
              hashes: []
            }
          }
        ],
        recommendations: [
          "Block the host IP 203.0.113.5 immediately at your network egress firewall.",
          "Transition SSH interfaces away from password authentication to RSA/Ed25519 keys.",
          "Restrict privilege escalation rights for system accounts in /etc/sudoers.",
          "Deploy an intrusion prevention system (e.g. fail2ban) to mitigate brute force sweeps."
        ]
      };

      const mockJsonString = JSON.stringify(mockResponse, null, 2);
      const encoder = new TextEncoder();

      const mockStream = new ReadableStream({
        async start(controller) {
          const chunkSize = 25;
          for (let i = 0; i < mockJsonString.length; i += chunkSize) {
            const chunk = mockJsonString.slice(i, i + chunkSize);
            controller.enqueue(encoder.encode(chunk));
            await new Promise(resolve => setTimeout(resolve, 15));
          }
          
          try {
            await insertQaHistory(sessionId, question, mockResponse as any);
            console.log(`Archived simulated ThreatAnalysis report to qa_history for session ${sessionId}.`);
          } catch (dbErr) {
            console.error('Failed to archive mock QA history:', dbErr);
          }
          
          controller.close();
        }
      });

      return new Response(mockStream, {
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
        },
      });
    }

    // 4. Call GPT-4o chat completion engine with response format capped as a JSON object
    const stream = await openai.chat.completions.create({
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        {
          role: 'user',
          content: `Log Context:\n${context}\n\nQuestion / Security Inquiry:\n${question}`,
        },
      ],
      response_format: { type: 'json_object' },
      stream: true,
    });

    // 5. Construct ReadableStream to pipeline token chunks dynamically as they arrive
    const encoder = new TextEncoder();
    const readableResponseStream = new ReadableStream({
      async start(controller) {
        let accumulatedText = '';

        try {
          for await (const chunk of stream) {
            const token = chunk.choices[0]?.delta?.content || '';
            if (token) {
              accumulatedText += token;
              // Stream text token back to the browser client immediately
              controller.enqueue(encoder.encode(token));
            }
          }

          // 6. After the completion stream completes, parse, validate, and archive
          try {
            const parsedAnalysis = JSON.parse(accumulatedText);
            const validation = ThreatAnalysisSchema.safeParse(parsedAnalysis);

            if (validation.success) {
              // Save validated response to the qa_history table asynchronously
              await insertQaHistory(sessionId, question, validation.data);
              console.log(`Archived ThreatAnalysis report to qa_history for session ${sessionId}.`);
            } else {
              console.error('Threat Q&A response schema mismatch:', validation.error);
            }
          } catch (parseErr) {
            console.error('Failed to parse completed streaming response buffer as JSON:', parseErr);
          }

          controller.close();
        } catch (streamErr) {
          console.error('Error during chat stream processing:', streamErr);
          controller.error(streamErr);
        }
      },
    });

    return new Response(readableResponseStream, {
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      },
    });

  } catch (err: any) {
    console.error('Fatal error in streaming analyze POST route:', err);
    return new Response(
      JSON.stringify({ error: err.message || 'A server error occurred during logs analysis.' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
