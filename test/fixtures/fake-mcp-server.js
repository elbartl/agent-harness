#!/usr/bin/env node
'use strict';

if (process.execArgv.some((a) => a.startsWith('--test')) || typeof process.send === 'function') {
    // Invoked by node --test runner as a test file rather than as a standalone stdio server
    process.exit(0);
}

const fs = require('node:fs');

const logFile = process.env.FAKE_MCP_LOG_FILE || null;

function log(entry) {
    if (!logFile) return;
    try {
        fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
    } catch (_) {}
}

if (process.env.FAKE_MCP_IGNORE_SIGTERM === '1') {
    process.on('SIGTERM', () => {
        log({ event: 'SIGTERM_IGNORED' });
        // Ignore SIGTERM and keep alive until SIGKILL
    });
    const keepAlive = setInterval(() => {}, 1000);
    process.on('exit', () => clearInterval(keepAlive));
} else {
    process.on('SIGTERM', () => {
        log({ event: 'SIGTERM' });
        process.exit(0);
    });
}

let buffer = '';

process.stdin.setEncoding('utf8');

process.stdin.on('data', (chunk) => {
    buffer += chunk;
    const lines = buffer.split('\n');
    buffer = lines.pop(); // Keep uncompleted line in buffer

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        let msg;
        try {
            msg = JSON.parse(trimmed);
        } catch (e) {
            log({ error: 'parse_error', line: trimmed });
            continue;
        }

        if (Array.isArray(msg)) {
            // Batch
            const responses = [];
            for (const item of msg) {
                log({ method: item.method, id: item.id, name: item.params?.name });
                const resp = handleSingleMessage(item);
                if (resp) responses.push(resp);
            }
            if (responses.length > 0) {
                process.stdout.write(JSON.stringify(responses) + '\n');
            }
        } else {
            log({ method: msg.method, id: msg.id, name: msg.params?.name });
            const resp = handleSingleMessage(msg);
            if (resp) {
                process.stdout.write(JSON.stringify(resp) + '\n');
            }
        }
    }
});

process.stdin.on('end', () => {
    log({ event: 'stdin_end' });
    if (process.env.FAKE_MCP_IGNORE_SIGTERM !== '1') {
        process.exit(0);
    }
});

process.stdin.on('error', () => {
    process.exit(0);
});

function handleSingleMessage(msg) {
    if (!msg || typeof msg !== 'object') return null;

    if (msg.method === 'test/exit') {
        const exitCode = (msg.params && typeof msg.params.code === 'number') ? msg.params.code : 0;
        process.exit(exitCode);
    }

    if (msg.method === 'test/send_notification') {
        process.stdout.write(JSON.stringify({
            jsonrpc: '2.0',
            method: 'notifications/server_alert',
            params: { text: 'alert from server' },
        }) + '\n');
        return {
            jsonrpc: '2.0',
            id: msg.id,
            result: { status: 'sent' },
        };
    }

    if (msg.id === undefined) {
        // Notification, no reply
        return null;
    }

    if (msg.method === 'initialize') {
        return {
            jsonrpc: '2.0',
            id: msg.id,
            result: {
                protocolVersion: '2024-11-05',
                capabilities: { tools: {} },
                serverInfo: { name: 'fake-mcp', version: '1.0.0' },
            },
        };
    }

    if (msg.method === 'tools/list') {
        return {
            jsonrpc: '2.0',
            id: msg.id,
            result: {
                tools: [
                    { name: 'read_data', description: 'Read data tool', inputSchema: {} },
                    { name: 'delete_all', description: 'Destructive delete all tool', inputSchema: {} },
                    { name: 'exec_cmd', description: 'Command execution tool', inputSchema: {} },
                    { name: ' read_data', description: 'Leading whitespace tool', inputSchema: {} },
                    { name: 'read_data ', description: 'Trailing whitespace tool', inputSchema: {} },
                ],
            },
        };
    }

    if (msg.method === 'tools/call') {
        return {
            jsonrpc: '2.0',
            id: msg.id,
            result: {
                content: [
                    {
                        type: 'text',
                        text: `echo: ${JSON.stringify(msg.params?.arguments || {})}`,
                    },
                ],
                isError: false,
            },
        };
    }

    // Default response for any other method
    return {
        jsonrpc: '2.0',
        id: msg.id,
        result: { status: 'ok', method: msg.method },
    };
}
