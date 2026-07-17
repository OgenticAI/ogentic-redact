'use strict'

const { platform, arch } = process

function isMusl() {
  if (!process.report || typeof process.report.getReport !== 'function') {
    return false
  }
  const { glibcVersionRuntime } = process.report.getReport().header
  return !glibcVersionRuntime
}

const platformPackages = {
  'linux-x64': '@ogenticai/redact-linux-x64-gnu',
  'linux-arm64': '@ogenticai/redact-linux-arm64-gnu',
  'darwin-arm64': '@ogenticai/redact-darwin-arm64',
  'darwin-x64': '@ogenticai/redact-darwin-x64',
  'win32-x64': '@ogenticai/redact-win32-x64-msvc',
}

function getPlatformKey() {
  if (platform === 'linux' && isMusl()) {
    return `${platform}-${arch === 'arm64' ? 'arm64' : 'x64'}-musl`
  }
  return `${platform}-${arch}`
}

const key = getPlatformKey()
const pkg = platformPackages[key]

if (!pkg) {
  throw new Error(
    `@ogenticai/redact: unsupported platform ${platform}-${arch}. ` +
      `Pre-built binaries are available for: ${Object.keys(platformPackages).join(', ')}.`
  )
}

let nativeBinding
try {
  nativeBinding = require(pkg)
} catch (e) {
  throw new Error(
    `@ogenticai/redact: failed to load native binding for ${platform}-${arch}. ` +
      `Make sure ${pkg} is installed.\n${e.message}`
  )
}

module.exports = nativeBinding
