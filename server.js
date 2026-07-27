require('dotenv').config();

const path = require('node:path');
const yauzl = require('yauzl');
const {
  AttachmentBuilder,
  Client,
  escapeMarkdown,
  Events,
  GatewayIntentBits,
  MessageFlags,
  PermissionFlagsBits,
  REST,
  Routes,
  SlashCommandBuilder,
} = require('discord.js');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const token = process.env.DISCORD_TOKEN;
const guildId = process.env.GUILD_ID;

if (!token) {
  console.error('DISCORD_TOKEN must be set in .env.');
  process.exit(1);
}

function positiveInteger(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer.`);
  }
  return value;
}

const limits = {
  maxZipBytes: positiveInteger('MAX_ZIP_BYTES', 25 * 1024 * 1024),
  maxEntries: positiveInteger('MAX_ZIP_ENTRIES', 100),
  maxSourceFiles: positiveInteger('MAX_SOURCE_FILES', 30),
  maxTotalUncompressedBytes: positiveInteger(
    'MAX_TOTAL_UNCOMPRESSED_BYTES',
    50 * 1024 * 1024,
  ),
  maxSingleFileBytes: positiveInteger('MAX_SINGLE_FILE_BYTES', 8 * 1024 * 1024),
  maxCompressionRatio: positiveInteger('MAX_COMPRESSION_RATIO', 250),
};

// ---------------------------------------------------------------------------
// Slash command
// ---------------------------------------------------------------------------

const sendFilesCommand = new SlashCommandBuilder()
  .setName('sendfiles')
  .setDescription('Extract source files from a ZIP and send them through a temporary webhook')
  .setDMPermission(false)
  .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
  .addAttachmentOption((option) =>
    option
      .setName('zip')
      .setDescription('The ZIP archive containing source code')
      .setRequired(true),
  );

// ---------------------------------------------------------------------------
// Safe ZIP extraction
// ---------------------------------------------------------------------------

const SOURCE_EXTENSIONS = new Set([
  '.asm', '.bash', '.c', '.cc', '.cfg', '.cjs', '.clj', '.cljs', '.cmake',
  '.conf', '.cpp', '.cs', '.css', '.dart', '.eex', '.el', '.ex', '.exs',
  '.fish', '.fs', '.fsx', '.go', '.gql', '.gradle', '.graphql', '.groovy',
  '.h', '.hh', '.hpp', '.htm', '.html', '.ini', '.java', '.js', '.json',
  '.jsonc', '.jsx', '.kt', '.kts', '.less', '.lua', '.m', '.md', '.mdx',
  '.mjs', '.mm', '.php', '.pl', '.pm', '.properties', '.proto', '.ps1',
  '.py', '.r', '.rb', '.rs', '.sass', '.scala', '.scss', '.sh', '.sol',
  '.sql', '.svelte', '.swift', '.toml', '.ts', '.tsx', '.txt', '.vb',
  '.vue', '.xml', '.yaml', '.yml', '.zig', '.zsh',
]);

const SOURCE_FILENAMES = new Set([
  '.env.example', '.gitignore', '.npmrc.example',
  'cmakelists.txt', 'dockerfile', 'gemfile', 'justfile', 'makefile',
  'procfile', 'rakefile',
]);

function isSourcePath(filePath) {
  const basename = path.posix.basename(filePath).toLowerCase();
  return SOURCE_FILENAMES.has(basename)
    || SOURCE_EXTENSIONS.has(path.posix.extname(basename));
}

function safeZipPath(rawName, isDirectory) {
  if (typeof rawName !== 'string' || rawName.includes('\0')) {
    throw new Error('The ZIP contains an invalid filename.');
  }

  const unified = rawName.replace(/\\/g, '/');
  if (unified.startsWith('/') || /^[a-zA-Z]:/.test(unified)) {
    throw new Error(`Unsafe absolute ZIP path: ${rawName}`);
  }
  if (unified.split('/').includes('..')) {
    throw new Error(`Unsafe parent-directory ZIP path: ${rawName}`);
  }

  const normalized = path.posix.normalize(unified);
  if (!normalized || normalized === '.' || normalized === '..'
      || normalized.startsWith('../')) {
    if (isDirectory) return normalized;
    throw new Error(`Invalid ZIP path: ${rawName}`);
  }
  if (normalized.length > 240) {
    throw new Error('The ZIP contains a path longer than 240 characters.');
  }

  return normalized;
}

function validateEntryType(entry, isDirectory) {
  const unixMode = (entry.externalFileAttributes >>> 16) & 0xffff;
  const fileType = unixMode & 0o170000;

  // A zero type is common for ZIPs made on non-Unix systems.
  if (fileType === 0) return;
  if (isDirectory && fileType === 0o040000) return;
  if (!isDirectory && fileType === 0o100000) return;

  throw new Error(`Special files and symbolic links are not allowed: ${entry.fileName}`);
}

function extractSourceFiles(zipBuffer) {
  return new Promise((resolve, reject) => {
    let zipFile;
    let settled = false;
    let entryCount = 0;
    let totalUncompressed = 0;
    const sourceFiles = [];

    const fail = (error) => {
      if (settled) return;
      settled = true;
      try {
        zipFile?.close();
      } catch {
        // Nothing else to do during failure cleanup.
      }
      reject(error instanceof Error ? error : new Error(String(error)));
    };

    yauzl.fromBuffer(
      zipBuffer,
      {
        lazyEntries: true,
        decodeStrings: true,
        validateEntrySizes: true,
      },
      (openError, openedZip) => {
        if (openError) {
          fail(new Error(`Could not read this ZIP: ${openError.message}`));
          return;
        }

        zipFile = openedZip;
        zipFile.once('error', fail);
        zipFile.once('end', () => {
          if (settled) return;
          settled = true;
          resolve(sourceFiles);
        });

        zipFile.on('entry', (entry) => {
          if (settled) return;

          try {
            entryCount += 1;
            if (entryCount > limits.maxEntries) {
              throw new Error(`The ZIP has more than ${limits.maxEntries} entries.`);
            }

            const isDirectory = /[\\/]$/.test(entry.fileName);
            const normalizedPath = safeZipPath(entry.fileName, isDirectory);
            validateEntryType(entry, isDirectory);

            if ((entry.generalPurposeBitFlag & 0x1) !== 0) {
              throw new Error(`Encrypted ZIP entries are not supported: ${entry.fileName}`);
            }

            if (isDirectory) {
              zipFile.readEntry();
              return;
            }

            totalUncompressed += entry.uncompressedSize;
            if (totalUncompressed > limits.maxTotalUncompressedBytes) {
              throw new Error(
                `The ZIP expands beyond the ${limits.maxTotalUncompressedBytes}-byte safety limit.`,
              );
            }

            if (entry.compressedSize > 0
                && entry.uncompressedSize / entry.compressedSize > limits.maxCompressionRatio) {
              throw new Error(`Suspicious compression ratio in: ${entry.fileName}`);
            }

            if (!isSourcePath(normalizedPath)) {
              zipFile.readEntry();
              return;
            }

            if (sourceFiles.length >= limits.maxSourceFiles) {
              throw new Error(
                `The ZIP contains more than ${limits.maxSourceFiles} supported source files.`,
              );
            }

            if (entry.uncompressedSize > limits.maxSingleFileBytes) {
              throw new Error(
                `Source file is larger than ${limits.maxSingleFileBytes} bytes: ${entry.fileName}`,
              );
            }

            zipFile.openReadStream(entry, (streamError, stream) => {
              if (streamError) {
                fail(new Error(`Could not extract ${entry.fileName}: ${streamError.message}`));
                return;
              }

              const chunks = [];
              let actualSize = 0;

              stream.on('data', (chunk) => {
                actualSize += chunk.length;
                if (actualSize > limits.maxSingleFileBytes
                    || actualSize > entry.uncompressedSize) {
                  stream.destroy(new Error(`Extracted data exceeded limits: ${entry.fileName}`));
                  return;
                }
                chunks.push(chunk);
              });

              stream.once('error', fail);
              stream.once('end', () => {
                if (settled) return;
                sourceFiles.push({
                  path: normalizedPath,
                  data: Buffer.concat(chunks, actualSize),
                });
                zipFile.readEntry();
              });
            });
          } catch (error) {
            fail(error);
          }
        });

        zipFile.readEntry();
      },
    );
  });
}

// ---------------------------------------------------------------------------
// Attachment download and webhook delivery
// ---------------------------------------------------------------------------

const LANGUAGE_BY_EXTENSION = {
  '.bash': 'bash', '.c': 'c', '.cjs': 'js', '.cpp': 'cpp', '.cs': 'cs',
  '.css': 'css', '.go': 'go', '.h': 'c', '.hpp': 'cpp', '.html': 'html',
  '.java': 'java', '.js': 'js', '.json': 'json', '.jsx': 'jsx', '.kt': 'kotlin',
  '.lua': 'lua', '.md': 'md', '.mjs': 'js', '.php': 'php', '.ps1': 'powershell',
  '.py': 'py', '.rb': 'rb', '.rs': 'rust', '.scss': 'scss', '.sh': 'bash',
  '.sql': 'sql', '.svelte': 'svelte', '.swift': 'swift', '.toml': 'toml',
  '.ts': 'ts', '.tsx': 'tsx', '.vue': 'vue', '.xml': 'xml', '.yaml': 'yaml',
  '.yml': 'yaml', '.zsh': 'bash',
};

function hasZipSignature(buffer) {
  if (buffer.length < 4) return false;
  const signature = buffer.readUInt32LE(0);
  return signature === 0x04034b50 // Local file header
    || signature === 0x06054b50   // Empty archive / end of central directory
    || signature === 0x08074b50;  // Spanned archive marker
}

async function downloadWithLimit(url, maxBytes) {
  const response = await fetch(url, {
    redirect: 'follow',
    signal: AbortSignal.timeout(30_000),
  });

  if (!response.ok || !response.body) {
    throw new Error(`Discord attachment download failed with HTTP ${response.status}.`);
  }

  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new Error(`The ZIP is larger than the ${maxBytes}-byte download limit.`);
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`The ZIP is larger than the ${maxBytes}-byte download limit.`);
    }
    chunks.push(Buffer.from(value));
  }

  return Buffer.concat(chunks, total);
}

function sourcePreview(file) {
  // Reserve room under Discord's 2,000-character message limit.
  if (file.data.length > 6_000) return null;

  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(file.data);
  } catch {
    return null;
  }

  if (text.length > 1_400 || text.includes('```')) return null;
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(text)) return null;
  return text;
}

function safeAttachmentName(filePath) {
  const basename = path.posix.basename(filePath)
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .slice(0, 100);
  return basename || 'source.txt';
}

async function sendSourceFile(webhook, threadId, file) {
  const shownPath = escapeMarkdown(file.path);
  const preview = sourcePreview(file);
  const common = {
    threadId,
    allowedMentions: { parse: [] },
  };

  if (preview !== null) {
    if (preview.length === 0) {
      await webhook.send({
        ...common,
        content: `**${shownPath}**\n_Empty file._`,
      });
    } else {
      const language = LANGUAGE_BY_EXTENSION[path.posix.extname(file.path).toLowerCase()] || '';
      await webhook.send({
        ...common,
        content: `**${shownPath}**\n\`\`\`${language}\n${preview}\n\`\`\``,
      });
    }
    return 'preview';
  }

  await webhook.send({
    ...common,
    content: `**${shownPath}** — attached because it is too long or is not UTF-8 text.`,
    files: [new AttachmentBuilder(file.data, { name: safeAttachmentName(file.path) })],
  });
  return 'attachment';
}

function channelForWebhook(channel) {
  // Webhooks cannot be created directly on threads. Create one on the parent
  // channel and target the current thread when sending.
  if (channel?.isThread?.()) {
    return { channel: channel.parent, threadId: channel.id };
  }
  return { channel, threadId: undefined };
}

// ---------------------------------------------------------------------------
// Discord client and /sendfiles handler
// ---------------------------------------------------------------------------

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

async function handleSendFiles(interaction) {
  if (!interaction.inGuild()
      || !interaction.memberPermissions?.has(PermissionFlagsBits.Administrator)) {
    await interaction.reply({
      content: 'Only server administrators can use `/sendfiles`.',
      flags: MessageFlags.Ephemeral,
    });
    return;
  }

  await interaction.deferReply({ flags: MessageFlags.Ephemeral });

  const attachment = interaction.options.getAttachment('zip', true);
  const target = channelForWebhook(interaction.channel);
  let webhook = null;
  let sentCount = 0;
  let previewCount = 0;
  let operationError = null;
  let cleanupError = null;

  try {
    if (!attachment.name.toLowerCase().endsWith('.zip')) {
      throw new Error('Upload a file whose name ends in `.zip`.');
    }
    if (attachment.size > limits.maxZipBytes) {
      throw new Error(`The ZIP is larger than the ${limits.maxZipBytes}-byte limit.`);
    }

    if (!target.channel || typeof target.channel.createWebhook !== 'function') {
      throw new Error('This channel type does not support webhooks.');
    }

    const botMember = interaction.guild.members.me;
    const permissions = target.channel.permissionsFor(botMember);
    if (!permissions?.has(PermissionFlagsBits.ViewChannel)
        || !permissions.has(PermissionFlagsBits.ManageWebhooks)) {
      throw new Error('I need View Channel and Manage Webhooks permissions here.');
    }

    const zipBuffer = await downloadWithLimit(attachment.url, limits.maxZipBytes);
    if (!hasZipSignature(zipBuffer)) {
      throw new Error('The uploaded file does not have a valid ZIP signature.');
    }

    const files = await extractSourceFiles(zipBuffer);
    if (files.length === 0) {
      throw new Error('No supported source-code or text files were found in the ZIP.');
    }

    webhook = await target.channel.createWebhook({
      name: 'Temporary ZIP Source Sender',
      avatar: client.user.displayAvatarURL({ extension: 'png', size: 128 }),
      reason: `/sendfiles requested by ${interaction.user.tag} (${interaction.user.id})`,
    });

    for (const file of files) {
      const delivery = await sendSourceFile(webhook, target.threadId, file);
      sentCount += 1;
      if (delivery === 'preview') previewCount += 1;
    }
  } catch (error) {
    operationError = error instanceof Error ? error : new Error(String(error));
    console.error('/sendfiles failed:', operationError);
  } finally {
    if (webhook) {
      try {
        await webhook.delete('Temporary /sendfiles webhook cleanup');
      } catch (error) {
        cleanupError = error instanceof Error ? error : new Error(String(error));
        console.error('Could not delete temporary webhook:', cleanupError);
      }
    }
  }

  if (operationError) {
    const partial = sentCount > 0 ? ` ${sentCount} file(s) were sent before the error.` : '';
    await interaction.editReply(
      `Could not process the ZIP: ${operationError.message.slice(0, 700)}${partial}`,
    );
    return;
  }

  const attachmentCount = sentCount - previewCount;
  const cleanupNote = cleanupError
    ? ' Warning: I could not delete the temporary webhook; an administrator should remove it.'
    : ' The temporary webhook was deleted.';
  await interaction.editReply(
    `Done: sent ${sentCount} source file(s) (${previewCount} previewed, `
      + `${attachmentCount} attached).${cleanupNote}`,
  );
}

client.once(Events.ClientReady, async (readyClient) => {
  console.log(`Logged in as ${readyClient.user.tag}.`);

  // Register /sendfiles automatically whenever server.js starts.
  try {
    const rest = new REST({ version: '10' }).setToken(token);
    const route = guildId
      ? Routes.applicationGuildCommands(readyClient.user.id, guildId)
      : Routes.applicationCommands(readyClient.user.id);

    await rest.put(route, { body: [sendFilesCommand.toJSON()] });
    console.log(
      guildId
        ? `Registered /sendfiles in guild ${guildId}.`
        : 'Registered /sendfiles globally. Global updates can take longer to appear.',
    );
  } catch (error) {
    console.error('Could not register /sendfiles:', error);
  }
});

client.on(Events.InteractionCreate, async (interaction) => {
  if (!interaction.isChatInputCommand() || interaction.commandName !== 'sendfiles') return;

  try {
    await handleSendFiles(interaction);
  } catch (error) {
    console.error('Unexpected interaction error:', error);
    const message = 'An unexpected error occurred while handling `/sendfiles`.';
    if (interaction.deferred || interaction.replied) {
      await interaction.editReply(message).catch(() => {});
    } else {
      await interaction.reply({ content: message, flags: MessageFlags.Ephemeral }).catch(() => {});
    }
  }
});

client.login(token);
