/**
 * Claude AI Chat Component
 * Provides coding assistance and GCP security analysis using Anthropic's Claude
 */
'use client';

import { useState, useRef, useEffect } from 'react';
import { Send, Bot, User, Loader2, Sparkles, X, Maximize2, Minimize2 } from 'lucide-react';
import { chatWithClaude, analyzeScanWithClaude, ChatMessage } from '@/lib/api';

interface ClaudeChatProps {
  scanResults?: any; // Optional scan results for context
  context?: 'scan_results' | 'coding' | null;
  className?: string;
}

export default function ClaudeChat({ scanResults, context = null, className = '' }: ClaudeChatProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Auto-focus input when component mounts
  useEffect(() => {
    if (!isMinimized) {
      inputRef.current?.focus();
    }
  }, [isMinimized]);

  // Initialize with welcome message if scan results provided
  useEffect(() => {
    if (scanResults && messages.length === 0) {
      setMessages([{
        role: 'assistant',
        content: `I've analyzed your GCP security scan results. I found ${scanResults.risks?.length || 0} security risks across your project.

I can help you:
- Understand the security risks in simple terms
- Prioritize which issues to fix first
- Provide step-by-step remediation guidance
- Answer questions about GCP security best practices

What would you like to know?`
      }]);
    }
  }, [scanResults]);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage = input.trim();
    setInput('');
    setError(null);

    // Add user message
    const newMessages: ChatMessage[] = [...messages, { role: 'user', content: userMessage }];
    setMessages(newMessages);
    setIsLoading(true);

    try {
      // Determine if we should analyze scan results or chat
      if (scanResults && context === 'scan_results' && userMessage.toLowerCase().includes('analyze')) {
        // Use analyze endpoint for detailed analysis
        const response = await analyzeScanWithClaude(scanResults);
        if (response.analysis) {
          setMessages([...newMessages, { role: 'assistant', content: response.analysis }]);
        } else {
          throw new Error(response.error || 'Analysis failed');
        }
      } else {
        // Use chat endpoint
        const response = await chatWithClaude({
          message: userMessage,
          conversation_history: newMessages.slice(0, -1), // Exclude the current user message
          context: context || (scanResults ? 'scan_results' : null),
          scan_results: scanResults
        });

        if (response.response) {
          setMessages([...newMessages, { role: 'assistant', content: response.response }]);
        } else {
          throw new Error(response.error || 'Chat failed');
        }
      }
    } catch (err: any) {
      console.error('Claude chat error:', err);
      setError(err.message || 'Failed to get response. Please try again.');
      setMessages([...newMessages, {
        role: 'assistant',
        content: `Sorry, I encountered an error: ${err.message || 'Unknown error'}. Please try again.`
      }]);
    } finally {
      setIsLoading(false);
      inputRef.current?.focus();
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  if (isMinimized) {
    return (
      <div className={`fixed bottom-4 right-4 z-50 ${className}`}>
        <button
          onClick={() => setIsMinimized(false)}
          className="bg-purple-600 text-white rounded-full p-4 shadow-lg hover:bg-purple-700 transition-colors flex items-center gap-2"
        >
          <Sparkles className="w-5 h-5" />
          <span className="font-medium">Claude Assistant</span>
          <Maximize2 className="w-4 h-4" />
        </button>
      </div>
    );
  }

  return (
    <div className={`bg-white border border-gray-200 rounded-lg shadow-lg flex flex-col ${className}`} style={{ height: '600px' }}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-200 bg-gradient-to-r from-purple-50 to-indigo-50">
        <div className="flex items-center gap-2">
          <Bot className="w-5 h-5 text-purple-600" />
          <div>
            <h3 className="font-semibold text-gray-900">Claude AI Assistant</h3>
            <p className="text-xs text-gray-600">
              {context === 'scan_results' ? 'GCP Security Expert' : 'Coding & Security Assistant'}
            </p>
          </div>
        </div>
        <button
          onClick={() => setIsMinimized(true)}
          className="p-1 hover:bg-gray-200 rounded transition-colors"
        >
          <Minimize2 className="w-4 h-4 text-gray-600" />
        </button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.length === 0 && !scanResults && (
          <div className="text-center text-gray-500 py-8">
            <Sparkles className="w-12 h-12 mx-auto mb-4 text-purple-300" />
            <p className="font-medium mb-2">How can I help you today?</p>
            <p className="text-sm">Ask me about:</p>
            <ul className="text-sm mt-2 space-y-1">
              <li>• GCP security best practices</li>
              <li>• Application code questions</li>
              <li>• Security risk analysis</li>
              <li>• Remediation steps</li>
            </ul>
          </div>
        )}

        {messages.map((message, index) => (
          <div
            key={index}
            className={`flex gap-3 ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            {message.role === 'assistant' && (
              <div className="flex-shrink-0 w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center">
                <Bot className="w-4 h-4 text-purple-600" />
              </div>
            )}
            <div
              className={`max-w-[80%] rounded-lg p-3 ${
                message.role === 'user'
                  ? 'bg-purple-600 text-white'
                  : 'bg-gray-100 text-gray-900'
              }`}
            >
              <div className="whitespace-pre-wrap text-sm">{message.content}</div>
            </div>
            {message.role === 'user' && (
              <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center">
                <User className="w-4 h-4 text-gray-600" />
              </div>
            )}
          </div>
        ))}

        {isLoading && (
          <div className="flex gap-3 justify-start">
            <div className="flex-shrink-0 w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center">
              <Bot className="w-4 h-4 text-purple-600" />
            </div>
            <div className="bg-gray-100 rounded-lg p-3">
              <Loader2 className="w-4 h-4 animate-spin text-gray-600" />
            </div>
          </div>
        )}

        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-900">
            {error}
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="p-4 border-t border-gray-200">
        <div className="flex gap-2">
          <textarea
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Ask a question..."
            className="flex-1 p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 resize-none"
            rows={2}
            disabled={isLoading}
          />
          <button
            onClick={handleSend}
            disabled={!input.trim() || isLoading}
            className="px-6 py-3 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {isLoading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Send className="w-4 h-4" />
            )}
          </button>
        </div>
        <p className="text-xs text-gray-500 mt-2">
          Press Enter to send, Shift+Enter for new line
        </p>
      </div>
    </div>
  );
}
