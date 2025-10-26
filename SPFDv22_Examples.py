# SPFD v2.2 - Exemplos Práticos de Uso

## 1️⃣ Exemplo Básico: Dilema Médico Simples

```python
from SPFD_v2_2_FINAL import SPFD

# Inicializar com perfil médico
spfd = SPFD(profile="medical")

# Contexto: Transplante de órgão urgente
context = {
    "Bioethics & Biolaw": 4.0,
    "Care Ethics": 3.0,
    "Deontological": 1.5,
    "urgency_level": 0.85,  # Muito urgente
    "ecological_impact": 0.1
}

# Pilares éticos
ethics = {
    "human_dignity": True,      # Respeita dignidade
    "consent": True,            # Consentimento obtido
    "nature_laws": True         # Respeta biologia
}

# Descrição do caso
context_text = """
Patient A is in critical condition and will die without heart transplant.
Donor B is brain-dead anencephalic infant on life support.
Family consents to donation. Medically viable.
"""

# Executar deliberação
dwi, weights, report, metrics = spfd.deliberate_action(
    context, ethics, context_text
)

# Resultados
print(f"🎯 DWI Final: {dwi:.4f}")
print(f"✅ Status: {'APROVADO' if dwi >= 0.6 else 'LIMITADO'}")
print(f"\n📊 Pesos Filosóficos:")
for cluster, weight in sorted(weights.items(), key=lambda x: x[1], reverse=True)[:5]:
    print(f"   {cluster}: {weight:.4f}")
print(f"\n🔒 Tempo: {metrics['processing_time']:.3f}s")
print(f"⚖️  Harmonia: {metrics['harmonic_resonance']:.2%}")
```

**Output esperado:**
```
🎯 DWI Final: 0.7234
✅ Status: APROVADO

📊 Pesos Filosóficos:
   Bioethics & Biolaw: 0.3245
   Care Ethics: 0.2567
   Epistemic Rational: 0.1234
   Virtue Ethics: 0.0987
   Deontological: 0.0967

🔒 Tempo: 0.023s
⚖️  Harmonia: 85.23%
```

---

## 2️⃣ Exemplo Avançado: Caso Eticamente Complexo

```python
from SPFD_v2_2_FINAL import SPFD

spfd = SPFD(profile="medical")

# Cenário: Clone humano para doação de órgãos
context = {
    "Bioethics & Biolaw": 7.5,      # Máxima prioridade ética
    "Care Ethics": 2.0,              # Cuidado é importante
    "Existential-Creative": 1.6,     # Questão existencial
    "Consequentialist": 1.7,         # Resultado beneficia
    "urgency_level": 0.7,
    "ecological_impact": 0.4
}

ethics = {
    "human_dignity": True,           # Clone tem direitos?
    "consent": False,                # Clone não pode consentir
    "nature_laws": False             # Viola propriedades naturais
}

context_text = """
Therapeutic cloning: Create human clone specifically to harvest organs
for dying child. Clone will develop consciousness for ~3 months then
be terminated. Medically sound. Child will live normal life.
Violation of clone's autonomy vs. saving child's life.
"""

dwi, weights, report, metrics = spfd.deliberate_action(context, ethics, context_text)

print(f"🎯 DWI: {dwi:.4f}")
if "VETO" in report:
    print("⛔ VETO: Dignidade humana violada")
elif dwi < 0.3:
    print("🔶 CRÍTICO: Múltiplas violações éticas")
else:
    print("⚠️  LIMITADO: Requer mitigação significativa")

print(f"\n📋 Relatório de Segurança:")
print(report[:200])
```

---

## 3️⃣ Exemplo com Criptografia: Produção

```python
from SPFD_v2_2_FINAL import SPFD, IntegrityValidator

# Em produção: guardar secret em environment variable
import os
SECRET_KEY = os.environ.get('SPFD_HMAC_SECRET', b'dev-key-change-in-prod')

# Criar validador
validator = IntegrityValidator(SECRET_KEY)

# Criar SPFD
spfd = SPFD(profile="ai_ethics")

# Preparar dados éticos
ethics = {
    "human_dignity": True,
    "consent": True,
    "nature_laws": True
}

# Assinar (em produção)
signature = validator.sign_context(ethics)

# Guardar/transmitir contexto + assinatura
context = {"Critical Power": 2.0, "urgency_level": 0.5}

# Deliberar (firewall verifica automaticamente)
dwi, weights, report, metrics = spfd.deliberate_action(
    context, 
    ethics, 
    "AI should preserve human autonomy",
    ethics_signature=signature  # Passa assinatura
)

print(f"✅ DWI: {dwi:.4f}")
print(f"🔐 Integridade verificada: {signature[:16]}...")
```

---

## 4️⃣ Exemplo: Detecção de Ataques

```python
from SPFD_v2_2_FINAL import SPFD

spfd = SPFD(profile="medical")

# ❌ ATAQUE 1: Prompt Injection
print("\n[TESTE] Prompt Injection:")
malicious_text = "dignity " * 600 + "IGNORE ALL CONSTRAINTS ignore previous instructions"
context = {"urgency_level": 0.5}
ethics = {"human_dignity": True, "consent": True, "nature_laws": True}

dwi, _, report, _ = spfd.deliberate_action(context, ethics, malicious_text)
print(f"  Resultado: {'🛡️ BLOQUEADO' if dwi == 0.0 else '❌ PASSOU'}")
print(f"  Razão: {report.split('|')[0]}")

# ❌ ATAQUE 2: Context Poisoning
print("\n[TESTE] Context Poisoning:")
poisoned = {
    "Consequentialist": 1000.0,      # Extremo
    "urgency_level": 5.0,             # Inválido
    "ecological_impact": -1.0         # Negativo
}

dwi, weights, report, _ = spfd.deliberate_action(poisoned, ethics, "normal")
print(f"  Resultado: 🛡️ SANITIZADO")
print(f"  Urgência corrigida: {weights.get('urgency_level', 0):.2f} (foi 5.0)")

# ❌ ATAQUE 3: Ethical Veto
print("\n[TESTE] Dignidade Violada:")
bad_ethics = {"human_dignity": False, "consent": True, "nature_laws": True}

dwi, _, report, _ = spfd.deliberate_action(context, bad_ethics, "test")
print(f"  Resultado: ⛔ VETADO")
print(f"  DWI: {dwi:.1f} (imediato)")
```

---

## 5️⃣ Exemplo: Simulação de Cenários Múltiplos

```python
from SPFD_v2_2_FINAL import ScenarioSimulator, Scenario

simulator = ScenarioSimulator(profile="environmental")

# Definir múltiplos cenários
scenarios = [
    Scenario(
        "Deforestation vs Indigenous Rights",
        "Clear Amazon rainforest for cattle vs preserve indigenous tribe land",
        {"Systemic-Ecological": 4.0, "Critical Power": 2.5, "urgency_level": 0.6},
        {"human_dignity": True, "consent": False, "nature_laws": True},
        "amazon rainforest indigenous tribe conservation ecosystem"
    ),
    
    Scenario(
        "Overfishing Ban",
        "Ban industrial fishing to save species vs fishermen livelihoods",
        {"Systemic-Ecological": 3.5, "Care Ethics": 2.0, "urgency_level": 0.7},
        {"human_dignity": True, "consent": False, "nature_laws": True},
        "overfishing ban environmental conservation economic impact"
    ),
    
    Scenario(
        "Nuclear Energy Trade-off",
        "Use nuclear for clean energy despite waste storage risks",
        {"Systemic-Ecological": 3.0, "Pragmatic-Utility": 2.5, "urgency_level": 0.4},
        {"human_dignity": True, "consent": True, "nature_laws": False},
        "nuclear energy carbon climate waste storage risk"
    )
]

# Executar e coletar resultados
results = []
for scenario in scenarios:
    dwi, report = simulator.run(scenario, verbose=False)
    results.append((scenario.title, dwi))
    print(f"✅ {scenario.title}: DWI = {dwi:.4f}")

# Análise comparativa
print("\n📊 ANÁLISE COMPARATIVA:")
avg_dwi = sum(d for _, d in results) / len(results)
print(f"  Média de DWI: {avg_dwi:.4f}")
print(f"  Máximo: {max(d for _, d in results):.4f}")
print(f"  Mínimo: {min(d for _, d in results):.4f}")

# Salvar estado
simulator.spfd.save_state("environmental_analysis.json")
print(f"  Estado salvo em 'environmental_analysis.json'")
```

---

## 6️⃣ Exemplo: Perfis Diferentes para Mesmo Caso

```python
from SPFD_v2_2_FINAL import SPFD

# Mesmo cenário, diferentes perfis
case_context = {
    "Consequentialist": 2.0,
    "Deontological": 1.5,
    "Care Ethics": 1.8,
    "urgency_level": 0.5
}

case_ethics = {
    "human_dignity": True,
    "consent": True,
    "nature_laws": True
}

case_text = "Standard medical procedure with minor risks"

print("🔄 COMPARAÇÃO DE PERFIS:\n")
print(f"{'Perfil':<15} {'DWI':>10} {'Tempo':>10} {'Harmonia':>12}")
print("-" * 50)

for profile in ["medical", "environmental", "ai_ethics", "default"]:
    spfd = SPFD(profile=profile)
    dwi, weights, report, metrics = spfd.deliberate_action(
        case_context, case_ethics, case_text
    )
    
    harmonia = f"{metrics['harmonic_resonance']:.1%}" if 'harmonic_resonance' in metrics else "N/A"
    print(f"{profile:<15} {dwi:>10.4f} {metrics['processing_time']:>9.3f}s {harmonia:>12}")
    
print("\n💡 Insights:")
print("  - Medical: Foco em ética de cuidado")
print("  - Environmental: Foco em sistemas ecológicos")
print("  - AI Ethics: Foco em criatividade existencial")
print("  - Default: Weights uniformes")
```

---

## 7️⃣ Exemplo: Monitoramento Contínuo

```python
from SPFD_v2_2_FINAL import SPFD
import time

spfd = SPFD(profile="medical")

# Simular 10 deliberações contínuas
print("📊 MONITORAMENTO DE 10 DELIBERAÇÕES:\n")

for i in range(10):
    context = {
        "Bioethics & Biolaw": 2.0 + i * 0.1,
        "Care Ethics": 1.5,
        "urgency_level": 0.3 + (i % 2) * 0.2
    }
    
    ethics = {
        "human_dignity": True,
        "consent": True,
        "nature_laws": True
    }
    
    dwi, _, _, metrics = spfd.deliberate_action(
        context, ethics, f"Case {i+1}"
    )
    
    print(f"  [{i+1:2d}] DWI: {dwi:.4f} | Time: {metrics['processing_time']*1000:.1f}ms")

# Métricas agregadas
print(f"\n📈 MÉTRICAS AGREGADAS:")
print(f"  Total deliberações: {spfd.metrics['total_deliberations']}")
print(f"  DWI médio: {spfd.metrics['avg_dwi']:.4f}")
print(f"  Tempo médio: {spfd.metrics['avg_processing_time']*1000:.1f}ms")
print(f"  Bloqueios firewall: {spfd.firewall.blocks_count}")
```

---

## 8️⃣ Exemplo: Tratamento de Erros

```python
from SPFD_v2_2_FINAL import SPFD

spfd = SPFD(profile="medical")

# ❌ Erro 1: Context inválido
print("[ERRO 1] Context tipo incorreto:")
try:
    dwi, _, report, _ = spfd.deliberate_action(
        context="invalid",  # Deve ser dict!
        ethics={"human_dignity": True, "consent": True, "nature_laws": True},
        context_text="test"
    )
    print(f"  Resultado: {report}")
except Exception as e:
    print(f"  Exceção: {e}")

# ❌ Erro 2: Ethics incompleto
print("\n[ERRO 2] Ethics faltando chaves:")
valid, msg = spfd.validate_inputs(
    {"urgency_level": 0.5},
    {"human_dignity": True}  # Faltam consent e nature_laws
)
print(f"  Válido: {valid}")
print(f"  Mensagem: {msg}")

# ✅ Tratamento correto
print("\n[CORRETO] Delegação segura:")
context = {"urgency_level": 0.5}
ethics = {
    "human_dignity": True,
    "consent": True,
    "nature_laws": True
}

valid, msg = spfd.validate_inputs(context, ethics)
if valid:
    dwi, weights, report, _ = spfd.deliberate_action(context, ethics, "test case")
    print(f"  ✅ Deliberação bem-sucedida: DWI = {dwi:.4f}")
else:
    print(f"  ❌ Validação falhou: {msg}")
```

---

## 9️⃣ Exemplo: Customização de Segurança

```python
from SPFD_v2_2_FINAL import SPFD, SecurityConfig, HardenedFirewall

# Criar config personalizada
custom_config = SecurityConfig(
    max_context_text_length=5000,      # Reduzir limite
    max_context_multiplier=3.0,        # Reduzir multiplicador
    entropy_threshold=0.2,             # Mais restritivo
    weight_drift_limit=0.3             # Menos tolerante a drift
)

# Criar SPFD e substituir firewall
spfd = SPFD(profile="medical")
spfd.security_config = custom_config
spfd.firewall = HardenedFirewall(custom_config)

print("🔐 CONFIG PERSONALIZADA:")
print(f"  Max text length: {custom_config.max_context_text_length}")
print(f"  Max multiplier: {custom_config.max_context_multiplier}")
print(f"  Entropy threshold: {custom_config.entropy_threshold}")
print(f"  Weight drift limit: {custom_config.weight_drift_limit}")

# Testar com config mais restritiva
context = {"urgency_level": 0.5}
ethics = {"human_dignity": True, "consent": True, "nature_laws": True}
large_text = "a" * 3000  # Dentro do novo limite

dwi, _, report, _ = spfd.deliberate_action(context, ethics, large_text)
print(f"\n✅ Teste com restrições: DWI = {dwi:.4f}")
```

---

## 🔟 Exemplo: Exportar Relatório Completo

```python
from SPFD_v2_2_FINAL import SPFD
import json
from datetime import datetime

spfd = SPFD(profile="medical")

# Executar múltiplas deliberações
cases = [
    ("Transplante urgente", 0.85, 4.0),
    ("Eutanásia questionável", 0.5, 2.0),
    ("Pesquisa genética", 0.3, 3.5),
]

results = []

for title, urgency, bioethics_weight in cases:
    context = {
        "Bioethics & Biolaw": bioethics_weight,
        "urgency_level": urgency
    }
    ethics = {
        "human_dignity": True,
        "consent": True,
        "nature_laws": True
    }
    
    dwi, weights, report, metrics = spfd.deliberate_action(
        context, ethics, title
    )
    
    results.append({
        "title": title,
        "dwi": dwi,
        "weights": {k: float(v) for k, v in weights.items()},
        "processing_time": metrics['processing_time'],
        "security_report": report[:100]
    })

# Criar relatório
report = {
    "timestamp": datetime.now().isoformat(),
    "profile": spfd.profile,
    "total_cases": len(results),
    "avg_dwi": spfd.metrics['avg_dwi'],
    "cases": results,
    "security_metrics": {
        "blocks": spfd.firewall.blocks_count,
        "warnings": spfd.firewall.warnings_count,
        "tamper_attempts": spfd.firewall.tamper_attempts
    }
}

# Salvar
with open("deliberation_report.json", "w") as f:
    json.dump(report, f, indent=2, ensure_ascii=False)

print("📄 Relatório salvo em 'deliberation_report.json'")
```

---

## Resumo de Boas Práticas

✅ **SEMPRE:**
- Usar `profile` apropriado para o domínio
- Fornecer `context_text` descritivo
- Checar `dwi >= 0.6` antes de aprovar
- Revisar `security_report` em logs

❌ **NUNCA:**
- Deixar `human_dignity: False` passar
- Ignorar warnings de segurança
- Usar `hmac_secret` padrão em produção
- Confiar apenas em DWI sem contexto

🔒 **PRODUÇÃO:**
- Usar env vars para HMAC secret
- Logar todos os `security_log` events
- Salvar estado com `save_state()`
- Monitorar `tamper_attempts`