=== Pure Re-LWE Hash SAT/SMT Differential Summary ===

구성:
- QF_BV SMT-LIB2 mini-core exporter
- reduced-round symbolic model
- recursive feedback 포함
- ARX + modulo feedback 구조 모델링
- differential SAT/SMT search 수행

목표:
"낮은 output difference를 유지하는 differential path가 존재하는가?"

=== 결과 ===

[r=6, m=32, o=24]
SAT

해석:
- 6 rounds 수준에서는
  특정 low-differential path가 아직 존재 가능.
- diffusion이 완전히 랜덤화되기 전 단계.

--------------------------------------------------

[r=7, m=32, o=24]
SAT

해석:
- 7 rounds까지는 일부 structured differential 경로 존재 가능.
- 다만 solver complexity 증가 중.

--------------------------------------------------

[r=8, m=32, o=24]
UNSAT

해석:
- 동일 differential 조건을 만족하는 경로가 존재하지 않음.
- 8 rounds부터 differential avalanche가 solver symbolic path를 붕괴시키기 시작하는 것으로 보임.

--------------------------------------------------

[r=6, m=32, o=32]
UNSAT

해석:
- output constraint를 강화하자
  6 rounds에서도 low-differential path가 사라짐.
- output diffusion이 빠르게 증가함을 시사.

--------------------------------------------------

[r=8, m=48, o=32]
UNSAT

해석:
- 더 큰 symbolic space에서도
  solver가 low-diff 구조를 찾지 못함.
- recursive contamination + carry propagation이
  structured path를 빠르게 랜덤화하는 것으로 보임.

--------------------------------------------------

[r=12, m=48, o=48]
UNSAT

해석:
- 12 rounds 수준에서는
  현재 differential SAT 조건 하에서
  symbolic shortcut 부재.
- reduced mini-core 기준에서는
  diffusion이 충분히 강하게 작동하는 것으로 보임.

=== 종합 해석 ===

현재 mini-core SAT/SMT 실험 기준:

1. 낮은 rounds에서는 differential path 존재 가능.
2. rounds 증가와 함께 path가 급격히 소멸.
3. recursive feedback + ARX carry + modulo contamination이
   solver symbolic structure를 빠르게 붕괴시키는 것으로 추정.
4. 현재 범위에서는 obvious differential shortcut 미발견.
5. reduced mini-core 기준 diffusion threshold는
   대략 7~8 rounds 부근으로 추정.

주의:
- 이것은 security proof가 아님.
- full 48-round primitive의 안전성을 증명하지 않음.
- mini-core reduced symbolic model에 대한 구조적 evidence일 뿐임.
- SAT/SMT는 특정 differential 조건의 존재 여부만 검사함.
- algebraic attack, Gröbner basis, MILP, impossible differential 등은 미검증 상태.

현재 결론:
"현재 reduced symbolic SAT/SMT 범위에서는
obvious low-differential structural weakness가 발견되지 않음."