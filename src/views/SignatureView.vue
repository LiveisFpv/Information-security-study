<script setup lang="ts">
import {
  ElGamal,
  type ElGamalKeyPair,
  type ElGamalPrivateKey,
  type ElGamalPublicKey,
  type ElGamalSignature,
} from "@/service/elgamal";
import { RSA, type KeyRSA, type KeysRSA } from "@/service/rsa";
import {
  parsePositiveBigInt,
  signElGamalPayload,
  signRsaPayload,
  signatureToJson,
  textToBytes,
  verifyElGamalPayload,
  verifyRsaPayload,
} from "@/service/signature";
import { computed, onBeforeUnmount, ref } from "vue";

type Algorithm = "rsa" | "elgamal";
type Action = "sign" | "verify";
type PayloadMode = "text" | "file" | "hash";
type KeyMode = "generated" | "manual";

const rsa = new RSA();
const elGamal = new ElGamal();

const algorithm = ref<Algorithm>("rsa");
const action = ref<Action>("sign");
const payloadMode = ref<PayloadMode>("text");
const keyMode = ref<KeyMode>("generated");

const generatedBits = ref(128);
const rsaGenerated = ref<KeysRSA | null>(null);
const elGamalGenerated = ref<ElGamalKeyPair | null>(null);

const textInput = ref("");
const fileInput = ref<File | null>(null);
const hashInput = ref("");

const rsaN = ref("");
const rsaE = ref("");
const rsaD = ref("");

const elP = ref("");
const elG = ref("");
const elX = ref("");
const elY = ref("");
const elK = ref("");

const rsaSignature = ref("");
const elR = ref("");
const elS = ref("");

const errors = ref<string[]>([]);
const resultText = ref("");
const success = ref<boolean | null>(null);
const downloadUrl = ref<string | null>(null);
const downloadName = ref("signature.json");

const inputLabel = computed(() => {
  if (payloadMode.value === "hash") return "Хэш-значение m (десятичное)";
  return payloadMode.value === "text" ? "Сообщение" : "Файл любого типа";
});

function revokeUrl() {
  if (downloadUrl.value) {
    URL.revokeObjectURL(downloadUrl.value);
    downloadUrl.value = null;
  }
}

function clearOutput() {
  success.value = null;
  resultText.value = "";
  revokeUrl();
}

function clearErrors() {
  errors.value = [];
}

function setDownloadObject(name: string, payload: object) {
  revokeUrl();
  downloadName.value = name;
  downloadUrl.value = URL.createObjectURL(
    new Blob([signatureToJson(payload)], { type: "application/json;charset=utf-8" })
  );
}

function onFileChange(event: Event) {
  const target = event.target as HTMLInputElement;
  fileInput.value = target.files?.[0] ?? null;
  clearOutput();
}

function parseDec(raw: string, fieldName: string): bigint {
  return parsePositiveBigInt(raw, fieldName);
}

function getGeneratedRsaPublic(): KeyRSA {
  if (!rsaGenerated.value) {
    throw new Error("Сначала сгенерируйте RSA-ключи.");
  }
  return rsaGenerated.value.openkey;
}

function getGeneratedRsaPrivate(): KeyRSA {
  if (!rsaGenerated.value) {
    throw new Error("Сначала сгенерируйте RSA-ключи.");
  }
  return rsaGenerated.value.closekey;
}

function getRsaPublicKey(): KeyRSA {
  if (keyMode.value === "generated") {
    return getGeneratedRsaPublic();
  }
  return {
    n: parseDec(rsaN.value, "RSA n"),
    key: parseDec(rsaE.value, "RSA e"),
  };
}

function getRsaPrivateKey(): KeyRSA {
  if (keyMode.value === "generated") {
    return getGeneratedRsaPrivate();
  }
  return {
    n: parseDec(rsaN.value, "RSA n"),
    key: parseDec(rsaD.value, "RSA d"),
  };
}

function getGeneratedElPublic(): ElGamalPublicKey {
  if (!elGamalGenerated.value) {
    throw new Error("Сначала сгенерируйте параметры Эль-Гамаля.");
  }
  return elGamalGenerated.value.publicKey;
}

function getGeneratedElPrivate(): ElGamalPrivateKey {
  if (!elGamalGenerated.value) {
    throw new Error("Сначала сгенерируйте параметры Эль-Гамаля.");
  }
  return elGamalGenerated.value.privateKey;
}

function getElPublicKey(): ElGamalPublicKey {
  if (keyMode.value === "generated") {
    return getGeneratedElPublic();
  }
  return {
    p: parseDec(elP.value, "p"),
    g: parseDec(elG.value, "g"),
    y: parseDec(elY.value, "y"),
  };
}

function getElPrivateKey(): ElGamalPrivateKey {
  if (keyMode.value === "generated") {
    return getGeneratedElPrivate();
  }
  return {
    p: parseDec(elP.value, "p"),
    g: parseDec(elG.value, "g"),
    x: parseDec(elX.value, "x"),
  };
}

function getManualHash(): bigint {
  return parseDec(hashInput.value, "m");
}

async function getPayloadBytes(): Promise<{ bytes: Uint8Array; sourceName: string }> {
  if (payloadMode.value === "text") {
    if (!textInput.value.length) {
      throw new Error("Введите сообщение.");
    }
    return { bytes: textToBytes(textInput.value), sourceName: "text" };
  }

  if (payloadMode.value === "file") {
    if (!fileInput.value) {
      throw new Error("Выберите файл.");
    }
    const sourceName = fileInput.value.name.replace(/\.[^.]+$/i, "") || "file";
    const buffer = await fileInput.value.arrayBuffer();
    return { bytes: new Uint8Array(buffer), sourceName };
  }

  throw new Error("Для этого режима нужен прямой ввод m.");
}

function format(lines: string[]) {
  resultText.value = lines.join("\n");
}

function buildBasePayload() {
  return {
    algorithm: algorithm.value.toUpperCase(),
    createdAt: new Date().toISOString(),
    sourceMode: payloadMode.value,
  };
}

function validateQuick(): boolean {
  const next: string[] = [];

  if (payloadMode.value === "text" && !textInput.value.length) {
    next.push("Введите сообщение.");
  }

  if (payloadMode.value === "file" && !fileInput.value) {
    next.push("Выберите файл.");
  }

  if (payloadMode.value === "hash" && !hashInput.value.trim()) {
    next.push("Введите хэш-значение m.");
  }

  if (action.value === "verify") {
    if (algorithm.value === "rsa" && !rsaSignature.value.trim()) {
      next.push("Введите подпись RSA.");
    }
    if (algorithm.value === "elgamal" && (!elR.value.trim() || !elS.value.trim())) {
      next.push("Введите компоненты подписи r и s.");
    }
  }

  errors.value = next;
  return next.length === 0;
}

function generateKeys() {
  clearErrors();
  clearOutput();
  try {
    if (algorithm.value === "rsa") {
      rsaGenerated.value = RSA.generate_keys(generatedBits.value);
      return;
    }
    elGamalGenerated.value = ElGamal.generateKeyPair(generatedBits.value);
  } catch (error) {
    errors.value = [error instanceof Error ? error.message : "Не удалось сгенерировать ключи."];
  }
}

async function signRsa() {
  const privateKey = getRsaPrivateKey();
  const publicKey = keyMode.value === "generated" ? getGeneratedRsaPublic() : getRsaPublicKey();

  if (payloadMode.value === "hash") {
    const m = getManualHash();
    const normalized = RSA.normalizeHash(m, privateKey.n);
    const signature = rsa.signHash(privateKey, m);
    const check = rsa.verifyHash(publicKey, m, signature);

    setDownloadObject("rsa_signature_hash.json", {
      ...buildBasePayload(),
      hash: {
        inputDecimal: m.toString(),
        normalizedDecimal: normalized.toString(),
      },
      signature: {
        decimal: signature.toString(),
      },
      publicKey: {
        n: publicKey.n.toString(),
        e: publicKey.key.toString(),
      },
    });

    success.value = check.valid;
    format([
      "Подпись RSA сформирована.",
      `m (вход): ${m.toString()}`,
      `m (нормализованное): ${normalized.toString()}`,
      `signature: ${signature.toString()}`,
      `Самопроверка: ${check.valid ? "успешно" : "ошибка"}`,
    ]);
    return;
  }

  const { bytes, sourceName } = await getPayloadBytes();
  const result = await signRsaPayload(privateKey, bytes);
  const check = await verifyRsaPayload(publicKey, result.signature, bytes);

  setDownloadObject(`${sourceName}_rsa_signature.json`, {
    ...buildBasePayload(),
    hash: {
      sha256Hex: result.hash.hex,
      sha256Decimal: result.hash.value.toString(),
      normalizedDecimal: result.normalizedHash.toString(),
    },
    signature: {
      decimal: result.signature.toString(),
    },
    publicKey: {
      n: publicKey.n.toString(),
      e: publicKey.key.toString(),
    },
  });

  success.value = check.valid;
  format([
    "Подпись RSA сформирована.",
    `SHA-256: ${result.hash.hex}`,
    `m (нормализованное): ${result.normalizedHash.toString()}`,
    `signature: ${result.signature.toString()}`,
    `Самопроверка: ${check.valid ? "успешно" : "ошибка"}`,
  ]);
}

async function verifyRsa() {
  const publicKey = getRsaPublicKey();
  const signature = parseDec(rsaSignature.value, "RSA signature");

  if (payloadMode.value === "hash") {
    const m = getManualHash();
    const verification = rsa.verifyHash(publicKey, m, signature);
    success.value = verification.valid;
    format([
      "Проверка RSA завершена.",
      `m (вход): ${m.toString()}`,
      `m (ожидаемое): ${RSA.normalizeHash(m, publicKey.n).toString()}`,
      `m (восстановленное): ${verification.recoveredHash.toString()}`,
      `Результат: ${verification.valid ? "подпись подлинна" : "подпись не подлинна"}`,
    ]);
    return;
  }

  const { bytes } = await getPayloadBytes();
  const verification = await verifyRsaPayload(publicKey, signature, bytes);
  success.value = verification.valid;
  format([
    "Проверка RSA завершена.",
    `SHA-256: ${verification.hash.hex}`,
    `m (ожидаемое): ${verification.normalizedHash.toString()}`,
    `m (восстановленное): ${verification.recoveredHash.toString()}`,
    `Результат: ${verification.valid ? "подпись подлинна" : "подпись не подлинна"}`,
  ]);
}

function buildElManualPublicFromX(privateKey: ElGamalPrivateKey): ElGamalPublicKey {
  const publicKey = ElGamal.buildPublicKey({ p: privateKey.p, g: privateKey.g }, privateKey.x);
  if (keyMode.value === "manual") {
    elY.value = publicKey.y.toString();
  }
  return publicKey;
}

function getOptionalForcedK(): bigint | undefined {
  if (!elK.value.trim()) {
    return undefined;
  }
  return parseDec(elK.value, "k");
}

async function signElgamal() {
  const privateKey = getElPrivateKey();
  const publicKey = keyMode.value === "generated" ? getGeneratedElPublic() : buildElManualPublicFromX(privateKey);
  const forcedK = getOptionalForcedK();

  if (payloadMode.value === "hash") {
    const m = getManualHash();
    const normalized = ElGamal.normalizeHash(m, privateKey.p);
    const signed = elGamal.signHash(privateKey, m, forcedK);
    const check = elGamal.verifyHash(publicKey, m, signed.signature);

    setDownloadObject("elgamal_signature_hash.json", {
      ...buildBasePayload(),
      hash: {
        inputDecimal: m.toString(),
        normalizedDecimal: normalized.toString(),
      },
      signature: {
        r: signed.signature.r.toString(),
        s: signed.signature.s.toString(),
      },
      parameters: {
        p: publicKey.p.toString(),
        g: publicKey.g.toString(),
        y: publicKey.y.toString(),
      },
      signing: {
        k: signed.k.toString(),
      },
    });

    success.value = check;
    format([
      "Подпись Эль-Гамаля сформирована.",
      `m (вход): ${m.toString()}`,
      `m (нормализованное): ${normalized.toString()}`,
      `Открытый ключ y: ${publicKey.y.toString()}`,
      `r: ${signed.signature.r.toString()}`,
      `s: ${signed.signature.s.toString()}`,
      `k: ${signed.k.toString()}`,
      `Самопроверка: ${check ? "успешно" : "ошибка"}`,
    ]);
    return;
  }

  const { bytes, sourceName } = await getPayloadBytes();
  const signed = await signElGamalPayload(privateKey, bytes, forcedK);
  const check = await verifyElGamalPayload(publicKey, signed.signature, bytes);

  setDownloadObject(`${sourceName}_elgamal_signature.json`, {
    ...buildBasePayload(),
    hash: {
      sha256Hex: signed.hash.hex,
      sha256Decimal: signed.hash.value.toString(),
      normalizedDecimal: signed.normalizedHash.toString(),
    },
    signature: {
      r: signed.signature.r.toString(),
      s: signed.signature.s.toString(),
    },
    parameters: {
      p: publicKey.p.toString(),
      g: publicKey.g.toString(),
      y: publicKey.y.toString(),
    },
    signing: {
      k: signed.k.toString(),
    },
  });

  success.value = check.valid;
  format([
    "Подпись Эль-Гамаля сформирована.",
    `SHA-256: ${signed.hash.hex}`,
    `m (нормализованное): ${signed.normalizedHash.toString()}`,
    `Открытый ключ y: ${publicKey.y.toString()}`,
    `r: ${signed.signature.r.toString()}`,
    `s: ${signed.signature.s.toString()}`,
    `k: ${signed.k.toString()}`,
    `Самопроверка: ${check.valid ? "успешно" : "ошибка"}`,
  ]);
}

async function verifyElgamal() {
  const publicKey = getElPublicKey();
  const signature: ElGamalSignature = {
    r: parseDec(elR.value, "r"),
    s: parseDec(elS.value, "s"),
  };

  if (payloadMode.value === "hash") {
    const m = getManualHash();
    const isValid = elGamal.verifyHash(publicKey, m, signature);
    success.value = isValid;
    format([
      "Проверка Эль-Гамаля завершена.",
      `m (вход): ${m.toString()}`,
      `m (нормализованное): ${ElGamal.normalizeHash(m, publicKey.p).toString()}`,
      `Результат: ${isValid ? "подпись подлинна" : "подпись не подлинна"}`,
    ]);
    return;
  }

  const { bytes } = await getPayloadBytes();
  const verification = await verifyElGamalPayload(publicKey, signature, bytes);
  success.value = verification.valid;
  format([
    "Проверка Эль-Гамаля завершена.",
    `SHA-256: ${verification.hash.hex}`,
    `m (нормализованное): ${verification.normalizedHash.toString()}`,
    `Результат: ${verification.valid ? "подпись подлинна" : "подпись не подлинна"}`,
  ]);
}

async function run() {
  clearErrors();
  clearOutput();

  if (!validateQuick()) {
    return;
  }

  try {
    if (algorithm.value === "rsa" && action.value === "sign") {
      await signRsa();
      return;
    }
    if (algorithm.value === "rsa" && action.value === "verify") {
      await verifyRsa();
      return;
    }
    if (algorithm.value === "elgamal" && action.value === "sign") {
      await signElgamal();
      return;
    }
    await verifyElgamal();
  } catch (error) {
    errors.value = [
      error instanceof Error ? error.message : "Не удалось выполнить операцию с электронной подписью.",
    ];
  }
}

onBeforeUnmount(() => {
  revokeUrl();
});
</script>

<template>
  <main class="sig-page">
    <section class="card">
      <h1>Электронная подпись: RSA и Эль-Гамаль</h1>

      <div class="row">
        <label class="inline">
          <span>Алгоритм</span>
          <select v-model="algorithm" class="input" @change="clearOutput">
            <option value="rsa">RSA</option>
            <option value="elgamal">Эль-Гамаль</option>
          </select>
        </label>

        <label class="inline">
          <span>Действие</span>
          <select v-model="action" class="input" @change="clearOutput">
            <option value="sign">Подписать</option>
            <option value="verify">Проверить</option>
          </select>
        </label>
      </div>

      <fieldset class="group">
        <legend>Ключи</legend>

        <div class="row">
          <label class="inline">
            <input v-model="keyMode" type="radio" value="generated" @change="clearOutput" />
            Сгенерировать
          </label>
          <label class="inline">
            <input v-model="keyMode" type="radio" value="manual" @change="clearOutput" />
            Ввести вручную
          </label>
        </div>

        <template v-if="keyMode === 'generated'">
          <label for="bits">Размер простых чисел (бит)</label>
          <select id="bits" v-model.number="generatedBits" class="input" @change="clearOutput">
            <option :value="128">128</option>
            <option :value="256">256</option>
            <option :value="512">512</option>
          </select>

          <button type="button" class="action" @click="generateKeys">Сгенерировать ключи</button>

          <template v-if="algorithm === 'rsa' && rsaGenerated">
            <label>n</label>
            <textarea class="input area small" :value="rsaGenerated.openkey.n.toString()" readonly />
            <label>e</label>
            <textarea class="input area small" :value="rsaGenerated.openkey.key.toString()" readonly />
            <label>d</label>
            <textarea class="input area small" :value="rsaGenerated.closekey.key.toString()" readonly />
          </template>

          <template v-if="algorithm === 'elgamal' && elGamalGenerated">
            <label>p</label>
            <textarea class="input area small" :value="elGamalGenerated.publicKey.p.toString()" readonly />
            <label>g</label>
            <textarea class="input area small" :value="elGamalGenerated.publicKey.g.toString()" readonly />
            <label>x</label>
            <textarea class="input area small" :value="elGamalGenerated.privateKey.x.toString()" readonly />
            <label>y</label>
            <textarea class="input area small" :value="elGamalGenerated.publicKey.y.toString()" readonly />
          </template>
        </template>

        <template v-else>
          <template v-if="algorithm === 'rsa'">
            <label>RSA n</label>
            <textarea v-model="rsaN" class="input area small" placeholder="Введите n" @input="clearOutput" />

            <template v-if="action === 'sign'">
              <label>RSA d</label>
              <textarea v-model="rsaD" class="input area small" placeholder="Введите d" @input="clearOutput" />
              <label>RSA e (для самопроверки и JSON)</label>
              <textarea v-model="rsaE" class="input area small" placeholder="Введите e" @input="clearOutput" />
            </template>

            <template v-else>
              <label>RSA e</label>
              <textarea v-model="rsaE" class="input area small" placeholder="Введите e" @input="clearOutput" />
            </template>
          </template>

          <template v-else>
            <label>p</label>
            <textarea v-model="elP" class="input area small" placeholder="Введите p" @input="clearOutput" />
            <label>g</label>
            <textarea v-model="elG" class="input area small" placeholder="Введите g" @input="clearOutput" />

            <template v-if="action === 'sign'">
              <label>x (секретный ключ)</label>
              <textarea v-model="elX" class="input area small" placeholder="Введите x" @input="clearOutput" />
              <label>k (необязательно, для варианта)</label>
              <textarea v-model="elK" class="input area small" placeholder="Введите k" @input="clearOutput" />
              <label>y (будет вычислен, можно оставить пустым)</label>
              <textarea v-model="elY" class="input area small" placeholder="y" @input="clearOutput" />
            </template>

            <template v-else>
              <label>y (открытый ключ)</label>
              <textarea v-model="elY" class="input area small" placeholder="Введите y" @input="clearOutput" />
            </template>
          </template>
        </template>
      </fieldset>

      <fieldset class="group">
        <legend>Сообщение / хэш</legend>

        <div class="row">
          <label class="inline">
            <input v-model="payloadMode" type="radio" value="text" @change="clearOutput" />
            Текст
          </label>
          <label class="inline">
            <input v-model="payloadMode" type="radio" value="file" @change="clearOutput" />
            Файл
          </label>
          <label class="inline">
            <input v-model="payloadMode" type="radio" value="hash" @change="clearOutput" />
            Готовый m
          </label>
        </div>

        <label>{{ inputLabel }}</label>

        <template v-if="payloadMode === 'text'">
          <textarea
            v-model="textInput"
            class="input area"
            placeholder="Введите текст сообщения"
            @input="clearOutput"
          />
        </template>

        <template v-else-if="payloadMode === 'file'">
          <input type="file" class="input" @change="onFileChange" />
        </template>

        <template v-else>
          <textarea
            v-model="hashInput"
            class="input area small"
            placeholder="Введите десятичное значение m"
            @input="clearOutput"
          />
        </template>
      </fieldset>

      <fieldset v-if="action === 'verify'" class="group">
        <legend>Подпись</legend>

        <template v-if="algorithm === 'rsa'">
          <label>Подпись RSA (десятичная)</label>
          <textarea
            v-model="rsaSignature"
            class="input area small"
            placeholder="Введите RSA-подпись"
            @input="clearOutput"
          />
        </template>

        <template v-else>
          <label>r</label>
          <textarea v-model="elR" class="input area small" placeholder="Введите r" @input="clearOutput" />
          <label>s</label>
          <textarea v-model="elS" class="input area small" placeholder="Введите s" @input="clearOutput" />
        </template>
      </fieldset>

      <button type="button" class="action primary" @click="run">
        {{ action === "sign" ? "Сформировать подпись" : "Проверить подпись" }}
      </button>

      <section v-if="errors.length" class="errors">
        <div v-for="(error, index) in errors" :key="index">{{ error }}</div>
      </section>

      <section v-if="resultText" class="result" :class="{ ok: success === true, bad: success === false }">
        <label>Результат</label>
        <textarea class="input area" :value="resultText" readonly />
        <a v-if="downloadUrl" class="action full" :href="downloadUrl" :download="downloadName">
          Скачать {{ downloadName }}
        </a>
      </section>
    </section>
  </main>
</template>

<style scoped>
.sig-page {
  width: 100%;
  display: flex;
  justify-content: center;
  padding: 24px 16px 40px;
}

.card {
  width: 100%;
  max-width: 980px;
  border: 1px solid #d4d8df;
  border-radius: 12px;
  padding: 20px;
  background: #fff;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

h1 {
  font-size: 22px;
  font-weight: 600;
  line-height: 1.3;
}

.group {
  border: 1px solid #d4d8df;
  border-radius: 10px;
  padding: 10px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.group legend {
  padding: 0 6px;
}

.row {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.inline {
  display: flex;
  align-items: center;
  gap: 8px;
}

.input {
  border: 1px solid #c5c9d3;
  border-radius: 8px;
  padding: 8px 10px;
  font-size: 15px;
}

.area {
  min-height: 120px;
  resize: vertical;
}

.area.small {
  min-height: 84px;
}

.action {
  border: 1px solid #3a78d4;
  border-radius: 8px;
  background: #eaf2ff;
  color: #113b7f;
  padding: 8px 12px;
  text-decoration: none;
  text-align: center;
  cursor: pointer;
}

.action.primary {
  background: #3a78d4;
  color: #fff;
}

.action.full {
  width: 100%;
}

.errors {
  border: 1px solid #d84545;
  border-radius: 8px;
  padding: 8px;
  color: #8b1111;
}

.result {
  display: flex;
  flex-direction: column;
  gap: 10px;
  border: 1px solid #d7dce5;
  border-radius: 10px;
  padding: 10px;
}

.result.ok {
  border-color: #4ca26f;
}

.result.bad {
  border-color: #c75555;
}

@media (max-width: 640px) {
  .card {
    padding: 14px;
  }

  h1 {
    font-size: 19px;
  }
}
</style>
