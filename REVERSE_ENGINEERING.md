# Pokémon Ultra Sun — análise reversa estática

**Estado:** reconhecimento do contêiner e análise inicial do executável ARM; a análise do jogo completo continua.  
**Data:** 2026-11-05  
**Escopo:** leitura estática, sem modificar a ROM. A ROM, o executável extraído, assets, textos e chaves não foram enviados a este repositório.

## Resultado do contêiner

A imagem indicada tem **4.294.967.296 bytes (4 GiB)**. Sua assinatura NCSD está em 0x100; o comprimento declarado (0x800000 unidades de 512 bytes) coincide com o tamanho observado. Foram encontradas quatro partições não vazias:

| Índice | Deslocamento (unidades de 512 bytes) | Tamanho (unidades de 512 bytes) | Deslocamento (bytes) | Tamanho (bytes) |
|---:|---:|---:|---:|---:|
| 0 | 0x20 | 0x6E12E8 | 16.384 | 3.693.465.600 |
| 1 | 0x6E1308 | 0x1018 | 3.693.481.984 | 2.109.440 |
| 6 | 0x6E2320 | 0x2F00 | 3.695.591.424 | 6.160.384 |
| 7 | 0x6E5220 | 0x11698 | 3.701.751.808 | 36.515.840 |

As partições foram reconhecidas como NCCH. A partição principal informa product code CTR-P-A2AA, program ID 0x00040000001B5000 e a flag NCCH “no crypto”. Essa constatação vem dos metadados e não exigiu busca ou uso de chaves.

## Executável principal

O ExeFS da partição principal lista .code, banner e icon. O componente .code tem **0x5A4000 bytes**, começa no arquivo CCI no deslocamento **0x7000**, e seu SHA-256 local confere com o hash armazenado no ExeFS:

b5388f7500d91be01499a99ca007c98212068608ed7c83c43952e1d5148e9e09

O ExHeader descreve os segmentos carregados:

| Segmento | Endereço | Tamanho de código | Espaço alocado |
|---|---:|---:|---:|
| Text | 0x00100000 | 0x4B99F0 | 0x4BA000 |
| Rodata | 0x005BA000 | 0xAC948 | 0xAD000 |
| Data | 0x00667000 | 0x3CD48 | 0x3D000 |

O byte de compressão do ExHeader é zero. Os tamanhos alocados somam 0x5A4000, consistente com o tamanho de .code. A cópia de trabalho desse componente permaneceu local para análise e não foi publicada.

## Startup analisado

O Ghidra 12.1.4 importou a imagem bruta como ARMv6 little-endian, mapeada em 0x00100000, sem executar análise automática do binário inteiro. O startup contém nove instruções:

| Endereço | Instrução observada |
|---:|---|
| 0x00100000 | bl 0x00100024 |
| 0x00100004 | bl 0x001045b4 |
| 0x00100008 | bl 0x0010693c |
| 0x0010000C | bl 0x00104628 |
| 0x00100010 | blx 0x00100ef0 |
| 0x00100014 | bl 0x00104580 |
| 0x00100018 | bl 0x00104608 |
| 0x0010001C | bl 0x00104500 |
| 0x00100020 | b 0x001044f8 |

A inspeção das funções chamadas diretamente pelo startup encontrou:

- **0x00100024:** laço que grava zero em palavras de 32 bits entre dois limites carregados de literais; comportamento compatível com zerar uma região de memória.
- **0x00104580:** a rotina percorre um intervalo de ponteiros via blx, mas os dois limites lidos dos literais adjacentes são iguais a 0x00666948 nesta versão; portanto, o laço não chama nenhuma entrada.
- **0x0010693c:** tem um caminho condicionado por bytes/ponteiros globais e inicializa vários campos de uma estrutura antes de chamar rotinas auxiliares; candidata a inicialização global sob condição.
- **0x00104628:** faz várias chamadas de preparação, calcula endereços a partir de constantes e passa parâmetros para outras rotinas; ainda não foi possível determinar o subsistema.
- **0x00104500:** chama repetidamente ponteiros indiretos obtidos de campos/slots e volta ao bloco em 0x0010456c; candidato a ciclo de despacho/atualização.
- **0x001044f8:** contém swi 0x3 seguido de retorno. O relatório registra a instrução, sem atribuir semântica de sistema ainda.

A rotina Thumb em **0x00100ef0** calcula o intervalo de uma tabela relativa entre 0x00665f5c e 0x00666948. A leitura dos slots dá **635 entradas únicas**; cada destino é calculado somando o deslocamento de 32 bits ao endereço do próprio slot. Todos os destinos normalizados ficam no segmento text: **632 ARM e 3 Thumb**. Os primeiros destinos incluem 0x005014d8, 0x004e3e98 e 0x0050c000; os três últimos são 0x00103ed1, 0x00103e85 e 0x00103e95. O script [list_ultrasun_initializers.py](analysis/list_ultrasun_initializers.py) reproduz a contagem e pode listar a tabela completa a partir de uma cópia local do .code. A rotina Thumb em 0x0030295c, chamada diretamente por muitos destinos ARM via blx, lê uma palavra de guarda, retorna 0 se ela já estiver marcada e, caso contrário, grava 1 e retorna 1. Esse comportamento é compatível com um helper de inicialização protegida contra repetição. Uma varredura de janela fixa encontrou chamada direta a esse helper nos primeiros 0x60 bytes de 482 dos 635 destinos; como ainda não foram inferidos os limites de cada função, a contagem é indicativa, não uma classificação definitiva. O script [count_guard_calls.py](analysis/count_guard_calls.py) reproduz essa varredura com Capstone. Os quatro primeiros mnemônicos dos destinos também se repetem: 358 começam com ldr/vldr/push/sub; outros 58 começam com ldr/vldr/vstr/bx, um padrão curto de gravação de valor carregado em um endereço global seguido de retorno. Isso sugere muitas inicializações de dados globais, mas não identifica quais variáveis ou subsistemas são afetados. O script de varredura imprime essas frequências. Em conjunto, o padrão reforça a hipótese de inicializadores estáticos, mas as funções chamadas ainda não foram todas identificadas semanticamente.\n\nEssas descrições são interpretações estáticas preliminares, não nomes simbólicos confirmados. O alvo 0x00100ef0 está em estado Thumb pelo blx do startup. A listagem ARM do Ghidra marcou só uma unidade nessa entrada, então conferi o mesmo offset em modo Thumb com Capstone: o trecho 0x00100ef0–0x00100f09 percorre outra tabela de ponteiros relativos, chama cada item com blx r0 e retorna quando chega ao limite. Isso confirma um segundo despachante de inicializadores no startup; sua extensão foi obtida da decodificação Thumb, não da contagem de bytes do Ghidra.

O script [AnalyzeUltraSunStartup.java](analysis/AnalyzeUltraSunStartup.java) repete a análise dos nove destinos, cria funções quando possível e imprime até 40 instruções por função. A última execução encontrou funções com 28, 76, 152, 172, 1, 44, 32, 128 e 8 bytes, respectivamente. O tamanho de 1 byte em 0x00100ef0 é uma limitação do passe atual, não uma estimativa confiável do tamanho real daquela rotina.

## Ferramentas

- **Ghidra 12.1.4** e **Eclipse Temurin JDK 25.0.5**: instalados localmente; usados para importar e inspecionar o executável ARM.
- **REA 6.8.0**: instalado localmente; o diagnóstico do provedor Ghidra passou. O comando de inspeção do REA recusou este arquivo bruto ARM no provedor Windows disponível, que não oferece esse formato/arquitetura nessa rota. A análise foi feita diretamente no Ghidra.
- **pyctr 0.7.6**: instalado localmente e usado para interpretar estruturas 3DS.
- **Capstone 5.0.9**: instalado localmente e usado para conferir a decodificação ARM.
- **3dstool**: não foi usado; não havia executável Windows disponível e a compilação exigiria ferramentas ausentes. A leitura das estruturas foi feita com pyctr e parsing direcionado.

Os utilitários e cópias de análise ficam na área local .tools/ e analysis_work/; somente este relatório e o script de análise foram publicados.

## Limites e próximas etapas

Esta é uma primeira passagem de engenharia reversa, não uma compreensão completa do jogo. A análise automática do binário inteiro foi interrompida por lentidão e referências a endereços não mapeados, então não há inventário global confiável de funções nem pseudocódigo completo. A próxima etapa é recuperar limites de função para os grupos mais comuns, identificar os alvos indiretos e os endereços globais que eles leem/escrevem e só então atribuir nomes semânticos.

A ROM original foi apenas lida. Nenhuma chave foi procurada ou usada. Não publicar a ROM, código extraído, assets, textos ou chaves.

## Referências

- [REA — projeto upstream](https://github.com/morluto/rea)
- [3dstool — código-fonte upstream](https://github.com/dnasdw/3dstool)
- [pyctr — código-fonte upstream](https://github.com/ihaveamac/pyctr)
- [Ghidra — projeto upstream](https://github.com/NationalSecurityAgency/ghidra)
- [Capstone — projeto upstream](https://github.com/capstone-engine/capstone)
