<script setup lang="ts">
import { RSA, type KeyRSA, type KeysRSA } from "@/service/rsa";
import { computed, onBeforeUnmount, ref } from "vue";

type Operation = "encrypt" | "decrypt";
type InputMode = "text" | "file";
type KeyMode = "generated" | "manual";

const rsa = new RSA();

const operation = ref<Operation>("encrypt");
const inputMode = ref<InputMode>("text");
const keyMode = ref<KeyMode>("generated");

const textInput = ref("");
const fileInput = ref<File | null>(null);

const generatedBits = ref(128);
const generatedKeys = ref<KeysRSA | null>(null);

const manualPublicExponent = ref("");
const manualPrivateExponent = ref("");
const manualModulus = ref("");

const outputText = ref("");
const outputFileName = ref("rsa_result.txt");
const outputUrl = ref<string | null>(null);
const showOutput = ref(false);
const errors = ref<string[]>([]);

const inputLabel = computed(() =>
  operation.value === "encrypt" ? "Открытый текст" : "Шифртекст (HEX)"
);

const outputLabel = computed(() =>
  operation.value === "encrypt" ? "Результат шифрования (HEX)" : "Результат дешифрования"
);

const activeExponentLabel = computed(() =>
  operation.value === "encrypt" ? "Открытая экспонента (e)" : "Закрытая экспонента (d)"
);

function revokeUrl(url: string | null) {
  if (url) URL.revokeObjectURL(url);
}

function clearOutput() {
  showOutput.value = false;
  outputText.value = "";
  revokeUrl(outputUrl.value);
  outputUrl.value = null;
}

function onUploadedFileChange(event: Event) {
  const target = event.target as HTMLInputElement;
  fileInput.value = target.files?.[0] ?? null;
  clearOutput();
}

function parsePositiveBigInt(raw: string, fieldName: string): bigint {
  const normalized = raw.trim();
  if (!/^\d+$/.test(normalized)) {
    throw new Error(`${fieldName} должно содержать только десятичные цифры.`);
  }
  const value = BigInt(normalized);
  if (value <= 0n) {
    throw new Error(`${fieldName} должно быть положительным целым числом.`);
  }
  return value;
}

function getActiveKey(): KeyRSA {
  if (keyMode.value === "generated") {
    if (!generatedKeys.value) {
      throw new Error("Сначала сгенерируйте ключи RSA.");
    }
    return operation.value === "encrypt"
      ? generatedKeys.value.openkey
      : generatedKeys.value.closekey;
  }

  const modulus = parsePositiveBigInt(manualModulus.value, "Модуль n");
  const exponent = parsePositiveBigInt(
    operation.value === "encrypt" ? manualPublicExponent.value : manualPrivateExponent.value,
    operation.value === "encrypt" ? "Открытая экспонента e" : "Закрытая экспонента d"
  );
  return { key: exponent, n: modulus };
}

function validate(): boolean {
  const nextErrors: string[] = [];

  if (inputMode.value === "text" && !textInput.value.length) {
    nextErrors.push("Введите входной текст.");
  }

  if (inputMode.value === "file" && !fileInput.value) {
    nextErrors.push("Выберите файл .txt.");
  }

  if (keyMode.value === "generated" && !generatedKeys.value) {
    nextErrors.push("Сгенерируйте пару ключей.");
  }

  if (keyMode.value === "manual") {
    try {
      parsePositiveBigInt(manualModulus.value, "Модуль n");
      if (operation.value === "encrypt") {
        parsePositiveBigInt(manualPublicExponent.value, "Открытая экспонента e");
      } else {
        parsePositiveBigInt(manualPrivateExponent.value, "Закрытая экспонента d");
      }
    } catch (error) {
      nextErrors.push(error instanceof Error ? error.message : "Некорректный ключ.");
    }
  }

  errors.value = nextErrors;
  return nextErrors.length === 0;
}

async function getInputPayload(): Promise<{ payload: string; name: string }> {
  if (inputMode.value === "text") {
    return { payload: textInput.value, name: "text_input" };
  }

  if (!fileInput.value) {
    throw new Error("Файл не выбран.");
  }

  const payload = await fileInput.value.text();
  const name = fileInput.value.name.replace(/\.[^.]+$/i, "") || "file_input";
  return { payload, name };
}

function generateKeys() {
  clearOutput();
  errors.value = [];
  try {
    generatedKeys.value = RSA.generate_keys(generatedBits.value);
  } catch (error) {
    errors.value = [error instanceof Error ? error.message : "Не удалось сгенерировать ключи RSA."];
  }
}

async function run() {
  clearOutput();
  if (!validate()) return;

  try {
    const key = getActiveKey();
    const { payload, name } = await getInputPayload();
    const result =
      operation.value === "encrypt" ? rsa.encrypt(key, payload) : rsa.decrypt(key, payload);

    outputText.value = result;
    outputFileName.value = `${name}_${operation.value === "encrypt" ? "зашифрован" : "дешифрован"}.txt`;
    outputUrl.value = URL.createObjectURL(new Blob([result], { type: "text/plain;charset=utf-8" }));
    showOutput.value = true;
  } catch (error) {
    errors.value = [error instanceof Error ? error.message : "Не удалось обработать данные."];
  }
}

onBeforeUnmount(() => {
  revokeUrl(outputUrl.value);
});
</script>

<template>
  <main class="rsa-page">
    <section class="card">
      <h1>Шифрование и дешифрование RSA</h1>

      <div class="row">
        <button
          type="button"
          class="toggle"
          :class="{ active: operation === 'encrypt' }"
          @click="
            operation = 'encrypt';
            clearOutput();
          "
        >
          Шифрование
        </button>
        <button
          type="button"
          class="toggle"
          :class="{ active: operation === 'decrypt' }"
          @click="
            operation = 'decrypt';
            clearOutput();
          "
        >
          Дешифрование
        </button>
      </div>

      <fieldset class="group">
        <legend>Источник ключей</legend>
        <label class="inline">
          <input v-model="keyMode" type="radio" value="generated" @change="clearOutput" />
          Сгенерированная пара ключей
        </label>
        <label class="inline">
          <input v-model="keyMode" type="radio" value="manual" @change="clearOutput" />
          Ручной ввод ключа
        </label>

        <template v-if="keyMode === 'generated'">
          <label for="key-size">Размер простых чисел (бит)</label>
          <select id="key-size" v-model.number="generatedBits" class="input" @change="clearOutput">
            <option :value="128">128</option>
            <option :value="256">256</option>
            <option :value="512">512</option>
            <option :value="1024">1024</option>
            <option :value="2048">2048</option>
            <option :value="4096">1024</option>
          </select>

          <button type="button" class="action" @click="generateKeys">Сгенерировать ключи</button>

          <template v-if="generatedKeys">
            <label for="generated-n">Модуль n</label>
            <textarea
              id="generated-n"
              class="input area small"
              :value="generatedKeys.openkey.n.toString()"
              readonly
            />

            <label for="generated-e">Открытая экспонента e</label>
            <textarea
              id="generated-e"
              class="input area small"
              :value="generatedKeys.openkey.key.toString()"
              readonly
            />

            <label for="generated-d">Закрытая экспонента d</label>
            <textarea
              id="generated-d"
              class="input area small"
              :value="generatedKeys.closekey.key.toString()"
              readonly
            />
          </template>
        </template>

        <template v-else>
          <label for="manual-n">Модуль n (десятичный)</label>
          <textarea
            id="manual-n"
            v-model="manualModulus"
            class="input area small"
            placeholder="Введите n"
            @input="clearOutput"
          />

          <template v-if="operation === 'encrypt'">
            <label for="manual-e">Открытая экспонента e (десятичная)</label>
            <textarea
              id="manual-e"
              v-model="manualPublicExponent"
              class="input area small"
              placeholder="Введите e"
              @input="clearOutput"
            />
          </template>

          <template v-else>
            <label for="manual-d">Закрытая экспонента d (десятичная)</label>
            <textarea
              id="manual-d"
              v-model="manualPrivateExponent"
              class="input area small"
              placeholder="Введите d"
              @input="clearOutput"
            />
          </template>
        </template>
      </fieldset>

      <fieldset class="group">
        <legend>Источник данных</legend>
        <label class="inline">
          <input v-model="inputMode" type="radio" value="text" @change="clearOutput" />
          Текст
        </label>
        <label class="inline">
          <input v-model="inputMode" type="radio" value="file" @change="clearOutput" />
          Файл (.txt)
        </label>

        <template v-if="inputMode === 'text'">
          <label for="text-input">{{ inputLabel }}</label>
          <textarea
            id="text-input"
            v-model="textInput"
            class="input area"
            :placeholder="operation === 'encrypt' ? 'Введите открытый текст' : 'Введите HEX-шифртекст'"
            @input="clearOutput"
          />
        </template>

        <template v-else>
          <label for="file-input">Входной файл .txt</label>
          <input id="file-input" type="file" accept=".txt,text/plain" @change="onUploadedFileChange" />
        </template>
      </fieldset>

      <button type="button" class="action primary" @click="run">
        {{ operation === "encrypt" ? "Выполнить шифрование" : "Выполнить дешифрование" }}
      </button>

      <section v-if="errors.length" class="errors">
        <div v-for="(err, idx) in errors" :key="idx">{{ err }}</div>
      </section>

      <section v-if="showOutput" class="result">
        <label for="result">{{ outputLabel }}</label>
        <textarea id="result" v-model="outputText" class="input area" readonly />
        <a class="action link full" :href="outputUrl!" :download="outputFileName">
          Скачать {{ outputFileName }}
        </a>
      </section>
    </section>
  </main>
</template>

<style scoped>
.rsa-page {
  width: 100%;
  display: flex;
  justify-content: center;
  padding: 24px 16px 40px;
}

.card {
  width: 100%;
  max-width: 900px;
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

.inline {
  display: flex;
  align-items: center;
  gap: 8px;
}

.row {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
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

.toggle {
  border: 1px solid #c5c9d3;
  background: #f6f8fb;
  color: #1f2735;
  border-radius: 8px;
  padding: 8px 12px;
  cursor: pointer;
}

.toggle.active {
  background: #dcecff;
  border-color: #70a7ff;
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

.hint {
  margin: 0;
  color: #4a5568;
  font-size: 14px;
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
