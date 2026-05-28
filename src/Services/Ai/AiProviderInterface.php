<?php

namespace App\Services\Ai;

interface AiProviderInterface
{
    /**
     * Send a message to the AI provider and get a response.
     *
     * @param  array  $history  Conversation history structure
     * @param  string  $systemPrompt  The system instruction
     * @return array Response data including text and potential tool calls
     */
    public function sendMessage(array $history, string $systemPrompt): array;
}
