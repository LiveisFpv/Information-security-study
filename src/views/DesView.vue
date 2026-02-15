<script setup lang="ts">
import { DES } from "@/service/des";
import { computed, onBeforeUnmount, ref } from "vue";

type Operation = "encrypt" | "decrypt";
type KeyMode = "manual" | "default";
type InputMode = "text" | "file" | "shell";
type BlockMode = "ecb";

const des = new DES();

const operation = ref<Operation>("encrypt");
const keyMode = ref<KeyMode>("manual");
const inputMode = ref<InputMode>("text");
const blockMode = ref<BlockMode>("ecb");

const manualKey = ref("");
const defaultKey = ref(DES.generateDefaultKeyHex());

const textInput = ref("");
const fileInput = ref<File | null>(null);

const shellFileName = ref("shell_input.txt");
const shellFileDraft = ref("");
const shellFileContent = ref("");
const shellFileUrl = ref<string | null>(null);

const outputText = ref("");
const outputFileName = ref("result.txt");
const outputUrl = ref<string | null>(null);

const errors = ref<string[]>([]);
const showOutput = ref(false);

const normalizedManualKey = computed(() => manualKey.value.trim().toUpperCase());
const activeKey = computed(() =>
  keyMode.value === "manual" ? normalizedManualKey.value : defaultKey.value,
);

const inputLabel = computed(() =>
  operation.value === "encrypt" ? "Исходный текст" : "Шифртекст (HEX)",
);

const outputLabel = computed(() =>
  operation.value === "encrypt" ? "Результат шифрования (HEX)" : "Результат дешифрования",
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

function refreshDefaultKey() {
  defaultKey.value = DES.generateDefaultKeyHex();
  clearOutput();
}

function onUploadedFileChange(event: Event) {
  const target = event.target as HTMLInputElement;
  fileInput.value = target.files?.[0] ?? null;
  clearOutput();
}

function createShellFile() {
  clearOutput();
  errors.value = [];

  if (!shellFileDraft.value.length) {
    errors.value = ["Введите содержимое файла, который нужно создать в оболочке."];
    return;
  }

  const safeName = (shellFileName.value.trim() || "shell_input.txt").replace(/[\\/:*?"<>|]/g, "_");
  shellFileName.value = safeName.toLowerCase().endsWith(".txt") ? safeName : `${safeName}.txt`;
  shellFileContent.value = shellFileDraft.value;

  revokeUrl(shellFileUrl.value);
  const blob = new Blob([shellFileContent.value], { type: "text/plain;charset=utf-8" });
  shellFileUrl.value = URL.createObjectURL(blob);
}

function validate(): boolean {
  const nextErrors: string[] = [];

  if (keyMode.value === "manual" && !DES.isValidKeyHex(normalizedManualKey.value)) {
    nextErrors.push("Ключ должен содержать ровно 16 HEX-символов (64 бита).");
  }

  if (inputMode.value === "text" && !textInput.value.length) {
    nextErrors.push("Введите входной текст.");
  }

  if (inputMode.value === "file" && !fileInput.value) {
    nextErrors.push("Выберите входной .txt файл.");
  }

  if (inputMode.value === "shell" && !shellFileContent.value.length) {
    nextErrors.push("Сначала создайте файл в оболочке.");
  }

  errors.value = nextErrors;
  return nextErrors.length === 0;
}

async function getInputPayload(): Promise<{ payload: string; name: string }> {
  if (inputMode.value === "text") {
    return { payload: textInput.value, name: "text_input" };
  }

  if (inputMode.value === "file") {
    if (!fileInput.value) throw new Error("Файл не выбран.");
    const payload = await fileInput.value.text();
    const name = fileInput.value.name.replace(/\.[^.]+$/i, "") || "file_input";
    return { payload, name };
  }

  const name = shellFileName.value.replace(/\.[^.]+$/i, "") || "shell_input";
  return { payload: shellFileContent.value, name };
}

async function run() {
  clearOutput();
  if (!validate()) return;

  try {
    const { payload, name } = await getInputPayload();
    const result =
      operation.value === "encrypt"
        ? des.encrypt(payload, activeKey.value, blockMode.value)
        : des.decrypt(payload, activeKey.value, blockMode.value);

    outputText.value = result;
    outputFileName.value = `${name}_${operation.value === "encrypt" ? "encrypted" : "decrypted"}.txt`;
    outputUrl.value = URL.createObjectURL(new Blob([result], { type: "text/plain;charset=utf-8" }));
    showOutput.value = true;
  } catch (error) {
    errors.value = [error instanceof Error ? error.message : "Не удалось обработать данные."];
  }
}

onBeforeUnmount(() => {
  revokeUrl(shellFileUrl.value);
  revokeUrl(outputUrl.value);
});
</script>

<template>
  <main class="des-page">
    <section class="card">
      <h1>Реализация шифра DES (сеть Фейстеля)</h1>

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

      <label for="mode">Режим DES</label>
      <select id="mode" v-model="blockMode" class="input" @change="clearOutput">
        <option value="ecb">ECB</option>
      </select>

      <fieldset class="group">
        <legend>Формирование ключа</legend>
        <label class="inline">
          <input
            v-model="keyMode"
            type="radio"
            value="manual"
            @change="clearOutput"
          />
          Ключ задан пользователем
        </label>
        <label class="inline">
          <input
            v-model="keyMode"
            type="radio"
            value="default"
            @change="clearOutput"
          />
          Ключ по умолчанию (генерация)
        </label>

        <template v-if="keyMode === 'manual'">
          <label for="manual-key">Ключ DES (HEX)</label>
          <input
            id="manual-key"
            v-model="manualKey"
            class="input"
            type="text"
            placeholder="Например: 133457799BBCDFF1"
            maxlength="16"
            @input="clearOutput"
          />
        </template>

        <template v-else>
          <label for="default-key">Сгенерированный ключ (HEX)</label>
          <div class="row">
            <input id="default-key" class="input grow" type="text" :value="defaultKey" readonly />
            <button type="button" class="action" @click="refreshDefaultKey">Обновить</button>
          </div>
        </template>
      </fieldset>

      <fieldset class="group">
        <legend>Источник данных</legend>
        <label class="inline">
          <input v-model="inputMode" type="radio" value="text" @change="clearOutput" />
          Ввод текста
        </label>
        <label class="inline">
          <input v-model="inputMode" type="radio" value="file" @change="clearOutput" />
          Файл с диска
        </label>
        <!-- <label class="inline">
          <input v-model="inputMode" type="radio" value="shell" @change="clearOutput" />
          Файл, созданный в оболочке
        </label> -->

        <template v-if="inputMode === 'text'">
          <label for="text-input">{{ inputLabel }}</label>
          <textarea
            id="text-input"
            v-model="textInput"
            class="input area"
            :placeholder="
              operation === 'encrypt'
                ? 'Введите открытый текст'
                : 'Вставьте HEX-строку, полученную при шифровании'
            "
            @input="clearOutput"
          />
        </template>

        <template v-if="inputMode === 'file'">
          <label for="file-input">Входной .txt файл</label>
          <input
            id="file-input"
            type="file"
            accept=".txt,text/plain"
            @change="onUploadedFileChange"
          />
        </template>

        <template v-if="inputMode === 'shell'">
          <label for="shell-name">Имя файла</label>
          <input
            id="shell-name"
            v-model="shellFileName"
            class="input"
            type="text"
            @input="clearOutput"
          />

          <label for="shell-content">Содержимое файла в оболочке</label>
          <textarea
            id="shell-content"
            v-model="shellFileDraft"
            class="input area"
            placeholder="Введите содержимое файла, затем нажмите кнопку создания"
            @input="clearOutput"
          />

          <div class="row">
            <button type="button" class="action grow" @click="createShellFile">Создать файл в оболочке</button>
            <a
              v-if="shellFileUrl"
              class="action link"
              :href="shellFileUrl"
              :download="shellFileName"
            >
              Скачать входной файл
            </a>
          </div>
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
.des-page {
  width: 100%;
  display: flex;
  justify-content: center;
  padding: 24px 16px 40px;
}

.card {
  width: 100%;
  max-width: 860px;
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

.grow {
  flex: 1;
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
