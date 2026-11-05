# Pokémon Ultra Sun — análise reversa

**Estado:** reconhecimento inicial; a engenharia reversa do conteúdo ainda não começou.  
**Data:** 2026-11-05  
**Alvo:** imagem CCI indicada pelo usuário. A ROM foi aberta somente para leitura; nenhum byte foi alterado.

## Resultado inicial

- O arquivo indicado está disponível localmente e mede **4.294.967.296 bytes (4 GiB)**.
- O cabeçalho contém a assinatura **NCSD** no deslocamento `0x100`.
- O tamanho declarado pelo cabeçalho é **8.388.608 unidades de 512 bytes**, igual ao tamanho observado do arquivo.
- A tabela NCSD contém entradas não vazias nos índices 0, 1, 6 e 7. As posições e tamanhos decodificados estão abaixo; isso ainda não confirma o conteúdo ou a descriptografia das partições.

| Índice | Deslocamento (unidades de 512 bytes) | Tamanho (unidades de 512 bytes) | Deslocamento (bytes) | Tamanho (bytes) |
|---:|---:|---:|---:|---:|
| 0 | 0x20 | 0x6E12E8 | 16.384 | 3.693.465.600 |
| 1 | 0x6E1308 | 0x1018 | 3.693.481.984 | 2.109.440 |
| 6 | 0x6E2320 | 0x2F00 | 3.695.591.424 | 6.160.384 |
| 7 | 0x6E5220 | 0x11698 | 3.701.751.808 | 36.515.840 |

## Ferramentas e limite atual

- O **REA** solicitado foi inspecionado no repositório upstream. Ele oferece fluxos de análise de binários e integração com motores como Ghidra, mas a documentação consultada não descreve um importador/extrator CCI/NCSD.
- O fluxo de binário bruto documentado pelo REA exige arquitetura e endereço de entrada explícitos. A documentação de ARM indica estado A32; portanto, não se deve assumir que um executável 3DS extraído será analisado corretamente por esse fluxo sem confirmar formato, mapeamento e estado ARM/Thumb.
- Neste ambiente, Python e GitHub CLI estão disponíveis. Node.js/npm, ctrtool, 3dstool, Ghidra e Rizin não foram encontrados. Assim, ainda não há extração de ExeFS/RomFS nem análise de código.
- O REA não foi instalado nem configurado, e nenhuma chave ou material de descriptografia foi procurado ou usado.

## Próximas etapas

1. Usar uma ferramenta 3DS livre e reconhecida (por exemplo, **3dstool** ou **ctrtool**) para validar o contêiner e inventariar as partições, sem escrever de volta na ROM.
2. Caso o conteúdo esteja criptografado, continuar apenas com uma cópia legitimamente descriptografada ou chaves que o usuário esteja autorizado a usar; não contornar proteção nem publicar chaves.
3. Extrair somente os componentes necessários para análise local, preservar hashes e registrar os comandos e versões das ferramentas.
4. Analisar executáveis ARM e dados com um desassemblador/decompilador adequado. Usar REA apenas nas entradas e formatos que seu provedor realmente aceite; complementar com Ghidra/objdump ou ferramentas 3DS quando necessário.
5. Publicar neste repositório notas, tabelas, hashes, mapas de símbolos e scripts de análise próprios. **Não publicar a ROM, código extraído, assets, textos ou chaves do jogo.**
6. Manter a ROM original intacta e verificar sua identidade antes/depois de qualquer etapa de leitura.

## Referências

- [REA — projeto upstream](https://github.com/morluto/rea)
- [REA — análise de binários brutos](https://github.com/morluto/rea/blob/main/docs/raw-binary.md)
- [REA — ferramentas de engenharia reversa](https://github.com/morluto/rea/blob/main/docs/reverse-engineering-tools.md)
- [3dstool — código-fonte upstream](https://github.com/dnasdw/3dstool)
- [3DS-rom-tools — referência de fluxo de extração CCI](https://github.com/ihaveamac/3DS-rom-tools/wiki/Extract-a-game-or-application-in-.3ds-or-.cci-format)

As referências descrevem projetos/ferramentas; não são evidência de que essas ferramentas estejam instaladas ou já tenham sido executadas nesta análise.
