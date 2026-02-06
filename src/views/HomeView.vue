<script setup lang="ts">
import { Encoder } from "@/service/encoder"
import { computed, onBeforeUnmount, ref } from "vue"

type Method = "vigenere" | "gamm"
type Mode = "encode" | "decode"

const mode = ref<Mode>("encode")
const method = ref<Method>("vigenere")

const inText = ref("")
const keyText = ref("")
const seedText = ref(0)
const inFile = ref<File | null>(null)

const errors = ref<string[]>([])
const isSubmitted = ref(false)

const showOutput = ref(false)
const resultText = ref("")
const downloadUrl = ref<string | null>(null)
const downloadName = ref<string>("result.txt")

const hasText = computed(() => inText.value.trim().length > 0)
const hasFile = computed(() => !!inFile.value)

const inLabel = computed(() =>
  mode.value === "encode" ? "Текст для шифрования" : "Текст для расшифровки"
)

const outLabel = computed(() =>
  mode.value === "encode" ? "Результат шифрования" : "Результат расшифровки"
)

function resetOutput() {
  showOutput.value = false
  resultText.value = ""
  if (downloadUrl.value) {
    URL.revokeObjectURL(downloadUrl.value)
    downloadUrl.value = null
  }
}

function validate(): boolean {
  errors.value = []
  if (method.value=="gamm"&&mode.value=="decode"&&seedText.value<0) errors.value.push("Введите ключ.")
  if (method.value!="gamm" && !keyText.value.trim()) errors.value.push("Введите ключ.")
  if (!hasText.value && !hasFile.value) {
    errors.value.push("Введите текст или прикрепите файл .txt.")
  }

  if (inFile.value) {
    const name = inFile.value.name.toLowerCase()
    if (!name.endsWith(".txt")) errors.value.push("Файл должен быть в формате .txt.")
  }

  return errors.value.length === 0
}

function onFileChange(e: Event) {
  resetOutput()
  const target = e.target as HTMLInputElement
  const file = target.files?.[0] ?? null
  inFile.value = file

  if (file) inText.value = ""
}

function onTextInput() {
  resetOutput()
  if (inText.value.trim().length > 0) inFile.value = null
}

async function runCipher() {
  isSubmitted.value = true
  resetOutput()
  if (!validate()) return

  const enc = new Encoder(keyText.value, method.value, seedText.value)

  if (inFile.value) {
    const originalName = inFile.value.name.replace(/\.txt$/i, "")
    downloadName.value =
      mode.value === "encode"
        ? `${originalName}_encrypted.txt`
        : `${originalName}_decrypted.txt`

    const content = await inFile.value.text()

    const processed =
      mode.value === "encode" ? enc.Encrypt(content) : enc.Decode(content)
    if (mode.value === "encode"){
      seedText.value=enc.seed
    }
    const blob = new Blob([processed], { type: "text/plain;charset=utf-8" })
    downloadUrl.value = URL.createObjectURL(blob)
    showOutput.value = true
    return
  }

  resultText.value =
    mode.value === "encode" ? enc.Encrypt(inText.value) : enc.Decode(inText.value)
  if (mode.value === "encode"){
      seedText.value=enc.seed
  }
  showOutput.value = true
}

function setMode(m: Mode) {
  if (mode.value === m) return
  mode.value = m
  resetOutput()
}

onBeforeUnmount(() => {
  if (downloadUrl.value) URL.revokeObjectURL(downloadUrl.value)
})
</script>

<template>
  <div class="nav">
    <button
      class="l_button"
      :class="{ selected: mode === 'encode' }"
      @click="setMode('encode')"
    >
      Зашифровать
    </button>
    <button
      class="r_button"
      :class="{ selected: mode === 'decode' }"
      @click="setMode('decode')"
    >
      Расшифровать
    </button>
  </div>

  <div class="main">
    <div class="main_window">
      <label for="method">Метод</label>
      <select id="method" class="input_text" v-model="method" @change="resetOutput">
        <option value="vigenere">Виженера</option>
        <option value="gamm">Гаммирование</option>
      </select>

      <label for="in_text">{{ inLabel }}</label>
      <textarea
        id="in_text"
        class="input_text"
        v-model="inText"
        @input="onTextInput"
        placeholder="Введите текст или выберите файл ниже"
      />

      <input type="file" name="in_file" accept=".txt,text/plain" @change="onFileChange" />

      
      <template v-if="method==='vigenere'">
        <label for="key_text">Ключ</label>
        <input
          id="key_text"
          type="text"
          class="input_text"
          v-model="keyText"
          @input="resetOutput"
          placeholder="Введите ключ"
        />
      </template>
      <template v-if="method==='gamm' && mode === 'encode' && showOutput">
        <label for="key_text">Ключ</label>
        <input
          id="key_text"
          type="number"
          class="input_text"
          v-model="seedText"
          @input="resetOutput"
        />
      </template>
      <template v-if="method==='gamm' && mode === 'decode'">
        <label for="key_text">Ключ</label>
        <input
          id="key_text"
          type="number"
          class="input_text"
          v-model="seedText"
          @input="resetOutput"
        />
      </template>


      <button type="button" class="input_text" @click="runCipher">
        {{ mode === "encode" ? "Зашифровать" : "Расшифровать" }}
      </button>

      <div v-if="isSubmitted && errors.length" class="errors">
        <div v-for="(err, idx) in errors" :key="idx">{{ err }}</div>
      </div>

      <template v-if="showOutput && !downloadUrl">
        <label for="result">{{ outLabel }}</label>
        <textarea id="result" class="input_text" v-model="resultText" rows="6"></textarea>
      </template>

      <template v-if="showOutput && downloadUrl">
        <label>Готовый файл</label>
        <a class="input_text download_link" :href="downloadUrl" :download="downloadName">
          Скачать {{ downloadName }}
        </a>
      </template>
    </div>
  </div>
</template>

<style scoped>
.nav{
  width: 100%;
  display: flex;
  flex-direction: row;
  justify-content: center;
  margin-top: 4vh;
  flex-wrap: wrap;
  gap: 0px;
}

.main{
  width: 100%;
  display: flex;
  flex-direction: row;
  justify-content: center;
  margin-top: 4vh;
  flex-wrap: wrap;
  gap: 50px
}

.main_window{
  width: 100%;
  display: flex;
  flex-direction: column;
  max-width: 400px;
  gap:10px;
}

.input_text, .l_button, .r_button{
  border-radius: 7px;
  font-size: 16px;
  padding: 4px 8px;
}

.l_button, .r_button{
  border: 0px;
  padding: 8px 8px;
}

.l_button{
  border-top-right-radius: 0px;
  border-bottom-right-radius: 0px;
  border-right: 1px solid gray;
}

.r_button{
  border-top-left-radius: 0px;
  border-bottom-left-radius: 0px;
}

.selected{
  background-color: rgb(177, 252, 177);
}

.errors{
  border: 1px solid #d33;
  border-radius: 7px;
  padding: 8px;
  font-size: 14px;
  line-height: 1.4;
}

.download_link{
  display: inline-block;
  text-decoration: none;
  cursor: pointer;
}
</style>
