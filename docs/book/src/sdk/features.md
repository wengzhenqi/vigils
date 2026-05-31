# SDK Feature Flags

## `ort`(default off)

```toml
vigil-sdk = { version = "0.13", features = ["ort"] }
```

启用后:
- ort crate + ONNX Runtime 1.24.4 dynamic lib
- 3-engine ensemble(OpenAI PF + xlmr-pii-v1 + yonigo-pii-v1)
- 8-class PrivacyLabel

不启用(default):
- 13 hard rules
- NoopEngine 占位
- 零 ONNX dep,sub-1s startup

## 选择

| Scenario | Feature |
|---|---|
| CLI tool wrap | default — 13 hard rules cover 90%+ leak,instant |
| Long-running agent | `ort` — recall ↑,11s cold + 419ms warm |
| Browser extension | default — size + cold start sensitive |

## Runtime env(if `ort`)

```bash
export ORT_DYLIB_PATH=$HOME/ort/onnxruntime-linux-x64-1.24.4/lib/libonnxruntime.so.1.24.4
export VIGIL_PRIVACY_FILTER_MODEL_DIR=/var/vigil/models/openai-pf/v1
```

详见 ADR 0012 / 0016 / 0017。
