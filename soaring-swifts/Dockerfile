FROM haskell:9.10@sha256:37a7585a7b9ce9237f67b3b430cbb9488734958a04c9d903a0e4bedc4b26b114 AS builder

WORKDIR /build
COPY branchless-compiler/ .

RUN cabal update && cabal build -j
RUN cp $(cabal list-bin branchless-compiler) /build/compiler

FROM haskell:9.10@sha256:37a7585a7b9ce9237f67b3b430cbb9488734958a04c9d903a0e4bedc4b26b114

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        nasm \
        binutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/compiler ./compiler
COPY chal.py .

ENTRYPOINT ["python3", "chal.py"]
