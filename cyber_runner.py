# cyber_runner.py
import logging
import random
import time
import json
from pathlib import Path
from pipeline.cyber_validator import validate_record, EXPECTED_CHECKS
from agent import cyber_rules as rules
from pipeline.learning import LearningStore
from agent.code_rewriter import replace_function_in_file
from agent.advanced_repair import apply_advanced_repair

logging.basicConfig(level=logging.INFO)

# ---- Ontology loader ----
def load_ontology(path="cyber_ontology.json"):
    try:
        with open(path) as f:
            data = json.load(f)
        possible = []
        for field, config in data.get("fields", {}).items():
            for op in config.get("normalizers", []):
                possible.append((field, op))
        return possible
    except FileNotFoundError:
        # Fallback hard‑coded list
        return [
            ('hsts', 'enable_hsts'),
            ('csp', 'add_csp'),
            ('sqli', 'mitigate_sqli'),
            ('spf', 'add_spf'),
            ('spf', 'add_spf_softfail'),
            ('ssl', 'renew_cert'),
            ('dir', 'block_directory'),
            ('rdp_port', 'block_rdp_port'),
            ('rdp_nla', 'enable_nla'),
            ('custom', 'create_custom_fix'),
            ('self_heal', 'fix_normalizer')
        ]

class CyberAgent:
    def __init__(self, population_size=20, generations=5, interval=30):
        self.base_population_size = population_size
        self.base_generations = generations
        self.interval = interval
        self.state = {}
        self.ALL_POSSIBLE = load_ontology()
        self.learning_store = LearningStore()
        self.max_possible = EXPECTED_CHECKS
        self.population = []
        self.fitnesses = []
        self.last_fitness = 0
        self.fitness_stagnation = 0
        self.meta_bounds = {
            "population_size": (10, 50),
            "generations": (3, 15),
            "mutation_rate": (0.1, 0.6)
        }

    def _default_meta(self):
        return {
            "population_size": self.base_population_size,
            "generations": self.base_generations,
            "mutation_rate": 0.3
        }

    def _random_chromosome(self):
        normalizers = random.sample(self.ALL_POSSIBLE, random.randint(0, 3))
        meta = {
            "population_size": random.randint(10, 50),
            "generations": random.randint(3, 15),
            "mutation_rate": round(random.uniform(0.1, 0.6), 2)
        }
        return (normalizers, meta)

    def _make_chromosome(self, normalizers, meta=None):
        if meta is None:
            meta = self._default_meta()
        return (normalizers, meta)

    def _fitness(self, chrom):
        if isinstance(chrom, tuple) and len(chrom) >= 2:
            norm, meta = chrom[0], chrom[1]
        else:
            norm = chrom if isinstance(chrom, list) else []
            meta = self._default_meta()

        from pipeline.cyber_validator import clear_normalizers, register_normalizer, apply_normalizers
        clear_normalizers()
        for field, op in norm:
            suggestion = {"field": field, "operation": op}
            normalizer = rules.create_normalizer_from_suggestion(suggestion)
            if normalizer:
                register_normalizer(normalizer)
        apply_normalizers(self.state)
        valid, errors = validate_record(self.state)

        coverage = max(0, self.max_possible - len(errors))
        penalty = max(0, (meta["population_size"] - 30) * 0.5)
        return coverage - penalty

    def _seed_from_learning_store(self):
        failures = self.learning_store.get_failures()
        if not failures:
            return []
        suggestions = rules.suggest_improvements(failures)
        if not suggestions:
            return []
        seeds = []
        combined = [(s["field"], s["operation"]) for s in suggestions]
        if combined:
            seeds.append(self._make_chromosome(combined))
        for s in suggestions:
            seeds.append(self._make_chromosome([(s["field"], s["operation"])]))
        return seeds

    def _crossover(self, chrom1, chrom2):
        if isinstance(chrom1, tuple) and len(chrom1) >= 2:
            norm1, meta1 = chrom1[0], chrom1[1]
        else:
            norm1 = chrom1 if isinstance(chrom1, list) else []
            meta1 = self._default_meta()
        if isinstance(chrom2, tuple) and len(chrom2) >= 2:
            norm2, meta2 = chrom2[0], chrom2[1]
        else:
            norm2 = chrom2 if isinstance(chrom2, list) else []
            meta2 = self._default_meta()

        p1_set = set(norm1)
        p2_set = set(norm2)
        common = p1_set.intersection(p2_set)
        u1 = list(p1_set - common)
        u2 = list(p2_set - common)
        random.shuffle(u1)
        random.shuffle(u2)
        split1 = len(u1)//2
        split2 = len(u2)//2
        child_norm = list(common) + u1[:split1] + u2[:split2]
        child_norm = list(dict.fromkeys(child_norm))

        child_meta = {}
        for key in meta1:
            if key in meta2:
                child_meta[key] = (meta1[key] + meta2[key]) / 2
            else:
                child_meta[key] = meta1[key]
        for key, bounds in self.meta_bounds.items():
            child_meta[key] = max(bounds[0], min(bounds[1], child_meta[key]))
            if key == "mutation_rate":
                child_meta[key] = round(child_meta[key], 2)
        return (child_norm, child_meta)

    def _mutate(self, chrom):
        if isinstance(chrom, tuple) and len(chrom) >= 2:
            norm, meta = chrom[0], chrom[1]
        else:
            norm = chrom if isinstance(chrom, list) else []
            meta = self._default_meta()

        new_norm = norm[:]
        if random.random() < meta["mutation_rate"]:
            action = random.choice(["add", "remove", "replace"])
            if action == "add" and len(new_norm) < len(self.ALL_POSSIBLE):
                available = [item for item in self.ALL_POSSIBLE if item not in set(new_norm)]
                if available:
                    new_norm.append(random.choice(available))
            elif action == "remove" and new_norm:
                idx = random.randint(0, len(new_norm)-1)
                new_norm.pop(idx)
            elif action == "replace" and new_norm:
                idx = random.randint(0, len(new_norm)-1)
                old = new_norm.pop(idx)
                available = [item for item in self.ALL_POSSIBLE if item not in set(new_norm)]
                if available:
                    new_norm.append(random.choice(available))
                else:
                    new_norm.insert(idx, old)

        for key in meta:
            if random.random() < 0.1:
                delta = random.uniform(-0.1, 0.1) * max(meta[key], 0.1)
                meta[key] += delta
                bounds = self.meta_bounds[key]
                meta[key] = max(bounds[0], min(bounds[1], meta[key]))
                if key == "mutation_rate":
                    meta[key] = round(meta[key], 2)
        return (new_norm, meta)

    def _repair_broken_code(self):
        failures = self.learning_store.get_failures()
        normalizer_errors = [f for f in failures if f.get("field_name") == "normalizer_failure"]
        if not normalizer_errors:
            logger.info("No normalizer errors to repair.")
            return
        # Try standard repair (traceback-based)
        latest = normalizer_errors[-1]
        traceback_str = latest.get("details", {}).get("traceback", "")
        if traceback_str:
            logger.warning(f"🛠️ Attempting self‑repair for error:\n{traceback_str}")
            new_code = rules.repair_function_from_traceback(traceback_str)
            if new_code:
                parsed = rules.parse_traceback(traceback_str)
                if parsed:
                    file_path = Path(parsed["file"])
                    func_name = parsed["function"]
                    success = replace_function_in_file(file_path, func_name, new_code)
                    if success:
                        logger.info(f"✅ Self‑repair successful for {func_name} in {file_path}")
                        self.fitness_stagnation = 0
                        return
                    else:
                        logger.error(f"❌ Self‑repair failed for {func_name} in {file_path}")
                else:
                    logger.error("❌ Could not parse traceback for file path")
            else:
                logger.warning("No standard repair generated")
        # If standard repair didn't help, try advanced pattern-based repair
        if self.fitness_stagnation > 0:  # only if stagnation persists
            logger.info("🔄 Trying advanced pattern-based repair")
            if apply_advanced_repair(failures):
                self.fitness_stagnation = 0
                logger.info("✅ Advanced repair applied successfully")
            else:
                logger.warning("❌ Advanced repair did not find a fix")

    def run_continuous(self):
        seeds = self._seed_from_learning_store()
        self.population = seeds if seeds else []
        while len(self.population) < self.base_population_size:
            self.population.append(self._random_chromosome())
        self.population.append(self._make_chromosome([]))
        self.fitnesses = [self._fitness(chrom) for chrom in self.population]

        while True:
            self.population, self.fitnesses = zip(*sorted(
                zip(self.population, self.fitnesses),
                key=lambda x: x[1],
                reverse=True
            ))
            self.population = list(self.population)
            self.fitnesses = list(self.fitnesses)

            best = self.population[0]
            best_meta = best[1]
            new_pop_size = int(best_meta["population_size"])
            self.base_generations = int(best_meta["generations"])
            current_mutation_rate = best_meta["mutation_rate"]

            if new_pop_size > len(self.population):
                while len(self.population) < new_pop_size:
                    self.population.append(self._random_chromosome())
            elif new_pop_size < len(self.population):
                self.population = self.population[:new_pop_size]
            self.fitnesses = [self._fitness(chrom) for chrom in self.population]
            self.base_population_size = new_pop_size

            if self.fitnesses[0] <= self.last_fitness:
                self.fitness_stagnation += 1
            else:
                self.fitness_stagnation = 0
            self.last_fitness = self.fitnesses[0]

            if self.fitness_stagnation >= 3:
                logger.warning("⚠️ Fitness stagnation detected – triggering self‑repair")
                self._repair_broken_code()
                self.fitnesses = [self._fitness(chrom) for chrom in self.population]
                self.fitness_stagnation = 0

            print(f"🏆 Best fitness: {self.fitnesses[0]:.2f}/{self.max_possible}")
            print(f"🧬 Normalizers: {best[0]}")
            print(f"⚙️  Meta: pop={self.base_population_size}, gen={self.base_generations}, mut={current_mutation_rate}")
            print(f"📊 Stagnation: {self.fitness_stagnation}")
            print(f"📄 Report saved to output/report.json")

            for _ in range(self.base_generations):
                new_pop = []
                new_pop.append(self.population[0])
                while len(new_pop) < self.base_population_size:
                    pop_len = len(self.population)
                    a = random.randint(0, pop_len-1)
                    b = random.randint(0, pop_len-1)
                    p1 = self.population[a] if self.fitnesses[a] >= self.fitnesses[b] else self.population[b]
                    c = random.randint(0, pop_len-1)
                    d = random.randint(0, pop_len-1)
                    p2 = self.population[c] if self.fitnesses[c] >= self.fitnesses[d] else self.population[d]
                    c1, c2 = self._crossover(p1, p2)
                    c1 = self._mutate(c1)
                    c2 = self._mutate(c2)
                    new_pop.extend([c1, c2])
                self.population = new_pop[:self.base_population_size]
                self.fitnesses = [self._fitness(chrom) for chrom in self.population]

            time.sleep(self.interval)

if __name__ == "__main__":
    agent = CyberAgent(population_size=20, generations=5, interval=5)
    agent.run_continuous()