// Development helper only. Preserves an existing binary and verifies official archives.
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { unzipSync } from "fflate";

const version = "9.4.1-15978811";
const hashes = {
  darwin: "eb93ce9d0fa121333f12395b3ab30822c5cdb9155737f20d342fe71809757059",
  linux: "f5bebd466ecf14d341fd465f2756a16d86052f29eb4532003d5ff7bcffd08de5",
  win32: "5fe3c8ee5c6b3f47efd1fced1d6418084037f54f13290816c5db717e6b5c92aa",
};
const platform = { darwin: "osx", linux: "linux", win32: "windows" }[
  process.platform
];
if (!platform) throw new Error("Unsupported platform");
const directory = resolve(dirname(fileURLToPath(import.meta.url)), "../tools");
const name = process.platform === "win32" ? "aapt2.exe" : "aapt2";
const binary = join(directory, name);
if (existsSync(binary) && !process.argv.includes("--update")) {
  console.log(
    execFileSync(binary, ["version"], {
      encoding: "utf8",
      timeout: 15000,
      windowsHide: true,
    }).trim(),
  );
  console.log("Existing binary preserved.");
} else {
  const url = `https://dl.google.com/dl/android/maven2/com/android/tools/build/aapt2/${version}/aapt2-${version}-${platform}.jar`;
  const response = await fetch(url, { signal: AbortSignal.timeout(60000) });
  if (!response.ok) throw new Error(`Download failed: HTTP ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (
    createHash("sha256").update(bytes).digest("hex") !==
    hashes[process.platform]
  )
    throw new Error("Archive SHA-256 mismatch");
  const files = unzipSync(bytes);
  if (!files[name]) throw new Error("aapt2 not present in archive");
  await mkdir(directory, { recursive: true });
  const temporary = await mkdtemp(join(directory, ".aapt2-"));
  try {
    const staged = join(temporary, name);
    await writeFile(staged, files[name]);
    await chmod(staged, 0o755);
    console.log(
      execFileSync(staged, ["version"], {
        encoding: "utf8",
        timeout: 15000,
        windowsHide: true,
      }).trim(),
    );
    if (files.NOTICE)
      await writeFile(join(directory, "aapt2-NOTICE.txt"), files.NOTICE);
    await rename(staged, binary);
  } finally {
    await rm(temporary, { recursive: true });
  }
}
