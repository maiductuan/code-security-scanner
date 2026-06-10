import type { LanguageConfig } from '../types/scanner.js';

// ─── Language Configurations ───────────────────────────────────────────────

const LANGUAGES: LanguageConfig[] = [
  {
    id: 'javascript',
    name: 'JavaScript',
    extensions: ['.js', '.jsx', '.mjs', '.cjs'],
    treeSitterLanguage: 'javascript',
    taintSources: [
      { pattern: 'req.body', type: 'user_input', description: 'Express request body' },
      { pattern: 'req.query', type: 'user_input', description: 'Express query parameters' },
      { pattern: 'req.params', type: 'user_input', description: 'Express route parameters' },
      { pattern: 'req.headers', type: 'user_input', description: 'HTTP request headers' },
      { pattern: 'document.location', type: 'user_input', description: 'Browser URL' },
      { pattern: 'window.location', type: 'user_input', description: 'Browser URL' },
      { pattern: 'document.cookie', type: 'user_input', description: 'Browser cookies' },
      { pattern: 'process.env', type: 'environment', description: 'Environment variables' },
      { pattern: 'localStorage.getItem', type: 'user_input', description: 'Local storage' },
      { pattern: 'document.getElementById', type: 'user_input', description: 'DOM element value' },
    ],
    taintSinks: [
      { pattern: 'eval($TAINTED)', type: 'code_injection', description: 'eval() call' },
      { pattern: 'innerHTML', type: 'xss', description: 'innerHTML assignment' },
      { pattern: 'document.write($TAINTED)', type: 'xss', description: 'document.write' },
      { pattern: 'exec($TAINTED)', type: 'command_injection', description: 'child_process.exec' },
      { pattern: 'execSync($TAINTED)', type: 'command_injection', description: 'child_process.execSync' },
      { pattern: 'query($TAINTED)', type: 'sql_injection', description: 'SQL query' },
      { pattern: 'raw($TAINTED)', type: 'sql_injection', description: 'Raw SQL query' },
    ],
    sanitizers: [
      { pattern: 'encodeURIComponent($X)', cleanses: ['xss'], description: 'URL encoding' },
      { pattern: 'escape($X)', cleanses: ['xss', 'sql_injection'], description: 'Generic escape' },
      { pattern: 'DOMPurify.sanitize($X)', cleanses: ['xss'], description: 'DOMPurify sanitizer' },
      { pattern: 'parseInt($X)', cleanses: ['sql_injection', 'xss'], description: 'Integer parsing' },
    ],
    namingConventions: {
      variables: 'camelCase',
      functions: 'camelCase',
      classes: 'PascalCase',
      constants: 'UPPER_SNAKE_CASE',
    },
    frameworks: ['express', 'react', 'vue', 'angular', 'next', 'nestjs', 'fastify', 'koa'],
    commentPatterns: { single: '//', multiStart: '/*', multiEnd: '*/' },
  },
  {
    id: 'typescript',
    name: 'TypeScript',
    extensions: ['.ts', '.tsx', '.mts', '.cts'],
    treeSitterLanguage: 'typescript',
    taintSources: [
      { pattern: 'req.body', type: 'user_input', description: 'Express request body' },
      { pattern: 'req.query', type: 'user_input', description: 'Express query parameters' },
      { pattern: 'req.params', type: 'user_input', description: 'Express route parameters' },
      { pattern: 'req.headers', type: 'user_input', description: 'HTTP request headers' },
      { pattern: 'process.env', type: 'environment', description: 'Environment variables' },
    ],
    taintSinks: [
      { pattern: 'eval($TAINTED)', type: 'code_injection', description: 'eval() call' },
      { pattern: 'innerHTML', type: 'xss', description: 'innerHTML assignment' },
      { pattern: 'exec($TAINTED)', type: 'command_injection', description: 'child_process.exec' },
      { pattern: 'query($TAINTED)', type: 'sql_injection', description: 'SQL query' },
    ],
    sanitizers: [
      { pattern: 'encodeURIComponent($X)', cleanses: ['xss'], description: 'URL encoding' },
      { pattern: 'parseInt($X)', cleanses: ['sql_injection', 'xss'], description: 'Integer parsing' },
    ],
    namingConventions: {
      variables: 'camelCase',
      functions: 'camelCase',
      classes: 'PascalCase',
      constants: 'UPPER_SNAKE_CASE',
    },
    frameworks: ['express', 'react', 'vue', 'angular', 'next', 'nestjs', 'fastify'],
    commentPatterns: { single: '//', multiStart: '/*', multiEnd: '*/' },
  },
  {
    id: 'python',
    name: 'Python',
    extensions: ['.py', '.pyw'],
    treeSitterLanguage: 'python',
    taintSources: [
      { pattern: 'request.form', type: 'user_input', description: 'Flask form data' },
      { pattern: 'request.args', type: 'user_input', description: 'Flask query args' },
      { pattern: 'request.json', type: 'user_input', description: 'Flask JSON body' },
      { pattern: 'request.data', type: 'user_input', description: 'Django request data' },
      { pattern: 'request.GET', type: 'user_input', description: 'Django GET params' },
      { pattern: 'request.POST', type: 'user_input', description: 'Django POST data' },
      { pattern: 'input()', type: 'user_input', description: 'Console input' },
      { pattern: 'os.environ', type: 'environment', description: 'Environment variables' },
      { pattern: 'sys.argv', type: 'user_input', description: 'CLI arguments' },
    ],
    taintSinks: [
      { pattern: 'eval($TAINTED)', type: 'code_injection', description: 'eval() call' },
      { pattern: 'exec($TAINTED)', type: 'code_injection', description: 'exec() call' },
      { pattern: 'os.system($TAINTED)', type: 'command_injection', description: 'OS command execution' },
      { pattern: 'subprocess.call($TAINTED)', type: 'command_injection', description: 'Subprocess call' },
      { pattern: 'cursor.execute($TAINTED)', type: 'sql_injection', description: 'SQL query' },
      { pattern: 'open($TAINTED)', type: 'path_traversal', description: 'File open' },
      { pattern: 'pickle.loads($TAINTED)', type: 'deserialization', description: 'Pickle deserialization' },
    ],
    sanitizers: [
      { pattern: 'bleach.clean($X)', cleanses: ['xss'], description: 'Bleach HTML sanitizer' },
      { pattern: 'escape($X)', cleanses: ['xss'], description: 'HTML escape' },
      { pattern: 'int($X)', cleanses: ['sql_injection'], description: 'Integer conversion' },
      { pattern: 'shlex.quote($X)', cleanses: ['command_injection'], description: 'Shell quoting' },
    ],
    namingConventions: {
      variables: 'snake_case',
      functions: 'snake_case',
      classes: 'PascalCase',
      constants: 'UPPER_SNAKE_CASE',
    },
    frameworks: ['django', 'flask', 'fastapi', 'tornado', 'pyramid', 'starlette'],
    commentPatterns: { single: '#', multiStart: '"""', multiEnd: '"""' },
  },
  {
    id: 'java',
    name: 'Java',
    extensions: ['.java'],
    treeSitterLanguage: 'java',
    taintSources: [
      { pattern: 'request.getParameter', type: 'user_input', description: 'Servlet parameter' },
      { pattern: 'request.getHeader', type: 'user_input', description: 'HTTP header' },
      { pattern: 'request.getInputStream', type: 'user_input', description: 'Request body' },
      { pattern: '@RequestParam', type: 'user_input', description: 'Spring request param' },
      { pattern: '@RequestBody', type: 'user_input', description: 'Spring request body' },
      { pattern: '@PathVariable', type: 'user_input', description: 'Spring path variable' },
      { pattern: 'Scanner.nextLine', type: 'user_input', description: 'Console input' },
    ],
    taintSinks: [
      { pattern: 'Runtime.exec($TAINTED)', type: 'command_injection', description: 'Runtime exec' },
      { pattern: 'Statement.execute($TAINTED)', type: 'sql_injection', description: 'SQL statement' },
      { pattern: 'Statement.executeQuery($TAINTED)', type: 'sql_injection', description: 'SQL query' },
      { pattern: 'new File($TAINTED)', type: 'path_traversal', description: 'File path' },
      { pattern: 'ObjectInputStream.readObject', type: 'deserialization', description: 'Deserialization' },
    ],
    sanitizers: [
      { pattern: 'PreparedStatement', cleanses: ['sql_injection'], description: 'Prepared statements' },
      { pattern: 'Integer.parseInt($X)', cleanses: ['sql_injection'], description: 'Integer parsing' },
      { pattern: 'ESAPI.encoder().encodeForHTML($X)', cleanses: ['xss'], description: 'ESAPI encoding' },
    ],
    namingConventions: {
      variables: 'camelCase',
      functions: 'camelCase',
      classes: 'PascalCase',
      constants: 'UPPER_SNAKE_CASE',
    },
    frameworks: ['spring', 'spring-boot', 'struts', 'jakarta', 'quarkus', 'micronaut'],
    commentPatterns: { single: '//', multiStart: '/*', multiEnd: '*/' },
  },
  {
    id: 'go',
    name: 'Go',
    extensions: ['.go'],
    treeSitterLanguage: 'go',
    taintSources: [
      { pattern: 'r.URL.Query', type: 'user_input', description: 'HTTP query params' },
      { pattern: 'r.FormValue', type: 'user_input', description: 'Form value' },
      { pattern: 'r.Body', type: 'user_input', description: 'Request body' },
      { pattern: 'r.Header.Get', type: 'user_input', description: 'HTTP header' },
      { pattern: 'os.Args', type: 'user_input', description: 'CLI arguments' },
      { pattern: 'os.Getenv', type: 'environment', description: 'Environment variable' },
    ],
    taintSinks: [
      { pattern: 'exec.Command($TAINTED)', type: 'command_injection', description: 'OS command' },
      { pattern: 'db.Query($TAINTED)', type: 'sql_injection', description: 'SQL query' },
      { pattern: 'db.Exec($TAINTED)', type: 'sql_injection', description: 'SQL exec' },
      { pattern: 'fmt.Fprintf(w, $TAINTED)', type: 'xss', description: 'HTTP response write' },
      { pattern: 'template.HTML($TAINTED)', type: 'xss', description: 'Unescaped HTML' },
      { pattern: 'os.Open($TAINTED)', type: 'path_traversal', description: 'File open' },
    ],
    sanitizers: [
      { pattern: 'template.HTMLEscapeString($X)', cleanses: ['xss'], description: 'HTML escaping' },
      { pattern: 'url.QueryEscape($X)', cleanses: ['xss'], description: 'URL escaping' },
      { pattern: 'strconv.Atoi($X)', cleanses: ['sql_injection'], description: 'String to int' },
    ],
    namingConventions: {
      variables: 'camelCase',
      functions: 'camelCase',
      classes: 'PascalCase',
      constants: 'camelCase',
    },
    frameworks: ['gin', 'echo', 'fiber', 'chi', 'gorilla', 'net/http'],
    commentPatterns: { single: '//', multiStart: '/*', multiEnd: '*/' },
  },
  {
    id: 'c',
    name: 'C',
    extensions: ['.c', '.h'],
    treeSitterLanguage: 'c',
    taintSources: [
      { pattern: 'argv', type: 'user_input', description: 'CLI arguments' },
      { pattern: 'scanf', type: 'user_input', description: 'Standard input' },
      { pattern: 'gets', type: 'user_input', description: 'Standard input (unsafe)' },
      { pattern: 'fgets', type: 'user_input', description: 'File/stdin input' },
      { pattern: 'getenv', type: 'environment', description: 'Environment variable' },
      { pattern: 'recv', type: 'network', description: 'Network receive' },
    ],
    taintSinks: [
      { pattern: 'system($TAINTED)', type: 'command_injection', description: 'System command' },
      { pattern: 'exec($TAINTED)', type: 'command_injection', description: 'Exec command' },
      { pattern: 'printf($TAINTED)', type: 'format_string', description: 'Format string' },
      { pattern: 'strcpy($BUF, $TAINTED)', type: 'buffer_overflow', description: 'Buffer copy' },
      { pattern: 'strcat($BUF, $TAINTED)', type: 'buffer_overflow', description: 'Buffer concat' },
    ],
    sanitizers: [],
    namingConventions: {
      variables: 'snake_case',
      functions: 'snake_case',
      classes: 'PascalCase',
      constants: 'UPPER_SNAKE_CASE',
    },
    frameworks: [],
    commentPatterns: { single: '//', multiStart: '/*', multiEnd: '*/' },
  },
  {
    id: 'cpp',
    name: 'C++',
    extensions: ['.cpp', '.cc', '.cxx', '.hpp', '.hh', '.hxx'],
    treeSitterLanguage: 'cpp',
    taintSources: [
      { pattern: 'argv', type: 'user_input', description: 'CLI arguments' },
      { pattern: 'cin', type: 'user_input', description: 'Standard input' },
      { pattern: 'getline', type: 'user_input', description: 'Line input' },
      { pattern: 'getenv', type: 'environment', description: 'Environment variable' },
    ],
    taintSinks: [
      { pattern: 'system($TAINTED)', type: 'command_injection', description: 'System command' },
      { pattern: 'strcpy($BUF, $TAINTED)', type: 'buffer_overflow', description: 'Buffer copy' },
      { pattern: 'sprintf($BUF, $TAINTED)', type: 'buffer_overflow', description: 'Sprintf' },
    ],
    sanitizers: [],
    namingConventions: {
      variables: 'camelCase',
      functions: 'camelCase',
      classes: 'PascalCase',
      constants: 'UPPER_SNAKE_CASE',
    },
    frameworks: ['qt', 'boost', 'poco'],
    commentPatterns: { single: '//', multiStart: '/*', multiEnd: '*/' },
  },
  {
    id: 'csharp',
    name: 'C#',
    extensions: ['.cs'],
    treeSitterLanguage: 'c_sharp',
    taintSources: [
      { pattern: 'Request.QueryString', type: 'user_input', description: 'Query string' },
      { pattern: 'Request.Form', type: 'user_input', description: 'Form data' },
      { pattern: 'Request.Headers', type: 'user_input', description: 'HTTP headers' },
    ],
    taintSinks: [
      { pattern: 'Process.Start($TAINTED)', type: 'command_injection', description: 'Process start' },
      { pattern: 'SqlCommand($TAINTED)', type: 'sql_injection', description: 'SQL command' },
    ],
    sanitizers: [
      { pattern: 'HttpUtility.HtmlEncode($X)', cleanses: ['xss'], description: 'HTML encoding' },
    ],
    namingConventions: {
      variables: 'camelCase',
      functions: 'PascalCase',
      classes: 'PascalCase',
      constants: 'PascalCase',
    },
    frameworks: ['aspnet', 'blazor', 'maui'],
    commentPatterns: { single: '//', multiStart: '/*', multiEnd: '*/' },
  },
  {
    id: 'php',
    name: 'PHP',
    extensions: ['.php', '.phtml'],
    treeSitterLanguage: 'php',
    taintSources: [
      { pattern: '$_GET', type: 'user_input', description: 'GET parameters' },
      { pattern: '$_POST', type: 'user_input', description: 'POST data' },
      { pattern: '$_REQUEST', type: 'user_input', description: 'Request data' },
      { pattern: '$_COOKIE', type: 'user_input', description: 'Cookie data' },
      { pattern: '$_SERVER', type: 'user_input', description: 'Server variables' },
      { pattern: '$_FILES', type: 'user_input', description: 'Uploaded files' },
    ],
    taintSinks: [
      { pattern: 'eval($TAINTED)', type: 'code_injection', description: 'eval()' },
      { pattern: 'exec($TAINTED)', type: 'command_injection', description: 'exec()' },
      { pattern: 'system($TAINTED)', type: 'command_injection', description: 'system()' },
      { pattern: 'mysql_query($TAINTED)', type: 'sql_injection', description: 'MySQL query' },
      { pattern: 'echo $TAINTED', type: 'xss', description: 'Echo output' },
      { pattern: 'include($TAINTED)', type: 'file_inclusion', description: 'File inclusion' },
    ],
    sanitizers: [
      { pattern: 'htmlspecialchars($X)', cleanses: ['xss'], description: 'HTML encoding' },
      { pattern: 'mysqli_real_escape_string($X)', cleanses: ['sql_injection'], description: 'SQL escaping' },
      { pattern: 'intval($X)', cleanses: ['sql_injection'], description: 'Integer conversion' },
    ],
    namingConventions: {
      variables: 'camelCase',
      functions: 'camelCase',
      classes: 'PascalCase',
      constants: 'UPPER_SNAKE_CASE',
    },
    frameworks: ['laravel', 'symfony', 'wordpress', 'drupal'],
    commentPatterns: { single: '//', multiStart: '/*', multiEnd: '*/' },
  },
  {
    id: 'ruby',
    name: 'Ruby',
    extensions: ['.rb', '.rake'],
    treeSitterLanguage: 'ruby',
    taintSources: [
      { pattern: 'params', type: 'user_input', description: 'Rails parameters' },
      { pattern: 'request.body', type: 'user_input', description: 'Request body' },
      { pattern: 'request.headers', type: 'user_input', description: 'HTTP headers' },
      { pattern: 'ENV', type: 'environment', description: 'Environment variables' },
    ],
    taintSinks: [
      { pattern: 'eval($TAINTED)', type: 'code_injection', description: 'eval()' },
      { pattern: 'system($TAINTED)', type: 'command_injection', description: 'system()' },
      { pattern: 'exec($TAINTED)', type: 'command_injection', description: 'exec()' },
      { pattern: '.where($TAINTED)', type: 'sql_injection', description: 'ActiveRecord where' },
      { pattern: 'raw($TAINTED)', type: 'xss', description: 'Raw HTML output' },
      { pattern: 'Marshal.load($TAINTED)', type: 'deserialization', description: 'Marshal deserialization' },
    ],
    sanitizers: [
      { pattern: 'sanitize($X)', cleanses: ['xss'], description: 'Rails sanitize' },
      { pattern: 'h($X)', cleanses: ['xss'], description: 'HTML escape helper' },
    ],
    namingConventions: {
      variables: 'snake_case',
      functions: 'snake_case',
      classes: 'PascalCase',
      constants: 'UPPER_SNAKE_CASE',
    },
    frameworks: ['rails', 'sinatra', 'hanami'],
    commentPatterns: { single: '#', multiStart: '=begin', multiEnd: '=end' },
  },
  {
    id: 'rust',
    name: 'Rust',
    extensions: ['.rs'],
    treeSitterLanguage: 'rust',
    taintSources: [
      { pattern: 'std::env::args', type: 'user_input', description: 'CLI arguments' },
      { pattern: 'std::io::stdin', type: 'user_input', description: 'Standard input' },
      { pattern: 'std::env::var', type: 'environment', description: 'Environment variable' },
    ],
    taintSinks: [
      { pattern: 'Command::new($TAINTED)', type: 'command_injection', description: 'OS command' },
      { pattern: 'format!($TAINTED)', type: 'format_string', description: 'Format string' },
    ],
    sanitizers: [],
    namingConventions: {
      variables: 'snake_case',
      functions: 'snake_case',
      classes: 'PascalCase',
      constants: 'UPPER_SNAKE_CASE',
    },
    frameworks: ['actix', 'rocket', 'axum', 'warp', 'tokio'],
    commentPatterns: { single: '//', multiStart: '/*', multiEnd: '*/' },
  },
  {
    id: 'kotlin',
    name: 'Kotlin',
    extensions: ['.kt', '.kts'],
    treeSitterLanguage: 'kotlin',
    taintSources: [
      { pattern: 'request.queryParams', type: 'user_input', description: 'Query parameters' },
      { pattern: 'call.receive', type: 'user_input', description: 'Ktor request body' },
    ],
    taintSinks: [
      { pattern: 'Runtime.exec($TAINTED)', type: 'command_injection', description: 'Runtime exec' },
      { pattern: 'createQuery($TAINTED)', type: 'sql_injection', description: 'JPA query' },
    ],
    sanitizers: [],
    namingConventions: {
      variables: 'camelCase',
      functions: 'camelCase',
      classes: 'PascalCase',
      constants: 'UPPER_SNAKE_CASE',
    },
    frameworks: ['ktor', 'spring-boot', 'android'],
    commentPatterns: { single: '//', multiStart: '/*', multiEnd: '*/' },
  },
  {
    id: 'swift',
    name: 'Swift',
    extensions: ['.swift'],
    treeSitterLanguage: 'swift',
    taintSources: [
      { pattern: 'URLRequest', type: 'network', description: 'URL request' },
      { pattern: 'UserDefaults', type: 'user_input', description: 'User defaults' },
    ],
    taintSinks: [
      { pattern: 'Process.launch', type: 'command_injection', description: 'Process launch' },
    ],
    sanitizers: [],
    namingConventions: {
      variables: 'camelCase',
      functions: 'camelCase',
      classes: 'PascalCase',
      constants: 'camelCase',
    },
    frameworks: ['vapor', 'swiftui', 'uikit'],
    commentPatterns: { single: '//', multiStart: '/*', multiEnd: '*/' },
  },
];

// ─── Registry Functions ────────────────────────────────────────────────────

/** Extension to language ID mapping (built from LANGUAGES) */
const EXTENSION_MAP = new Map<string, string>();
for (const lang of LANGUAGES) {
  for (const ext of lang.extensions) {
    EXTENSION_MAP.set(ext, lang.id);
  }
}

/**
 * Get language ID by file extension
 */
export function getLanguageByExtension(ext: string): string | null {
  return EXTENSION_MAP.get(ext.toLowerCase()) ?? null;
}

/**
 * Get full language configuration by ID
 */
export function getLanguageConfig(id: string): LanguageConfig | null {
  return LANGUAGES.find(l => l.id === id) ?? null;
}

/**
 * Get all registered languages
 */
export function getAllLanguages(): LanguageConfig[] {
  return LANGUAGES;
}

/**
 * Get all supported file extensions
 */
export function getSupportedExtensions(): string[] {
  return Array.from(EXTENSION_MAP.keys());
}

/**
 * Check if a language is supported
 */
export function isLanguageSupported(id: string): boolean {
  return LANGUAGES.some(l => l.id === id);
}
