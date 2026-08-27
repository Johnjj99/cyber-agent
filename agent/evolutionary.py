# agent/evolutionary.py
import random
import logging
import json
from typing import List, Tuple, Optional, Any, Union

from ontology import Ontology
from agent.code_modifier import add_normalizer_to_code, reload_dynamic_normalizers
from agent.tools import run_pipeline_tool, load_learning_failures

logger = logging.getLogger(__name__)


class EvolutionaryAgent:
    def __init__(
        self,
        input_path: str = "input/complex_data.json",
        population_size: int = 40,
        generations: int = 30,
        initial_mutation_rate: float = 0.3,
        elite_size: int = 3,
        use_learning_store: bool = True,
        permanent: bool = False,
        validator_module=None,
        rules_module=None,
        ontology_path: str = "ontology.json",
    ):
        self.input_path = input_path
        self.population_size = population_size
        self.generations = generations
        self.initial_mutation_rate = initial_mutation_rate
        self.elite_size = elite_size
        self.use_learning_store = use_learning_store
        self.permanent = permanent
        self.validator = validator_module
        self.rules = rules_module
        self.ontology = Ontology(ontology_path)

        self.max_possible = 0
        self.best_ever = None          # chromosome with best fitness
        self.best_fitness = -1

        self.ALL_POSSIBLE = self._build_possible_operations()
        self._cache = {}               # for fitness caching

    def _build_possible_operations(self) -> List[Tuple[str, str]]:
        all_ops = []
        for field_name in self.ontology.field_defs:
            normalizers = self.ontology.get_normalizers(field_name)
            for op in normalizers:
                all_ops.append((field_name, op))
        if not all_ops:
            fallback_fields = ["ssl_days", "hsts", "hsts_subdomains", "port_80", "tls_version",
                               "csp_present", "x_content_type_options", "referrer_policy",
                               "cookie_secure", "cookie_httponly"]
            fallback_ops = ["renew_cert", "enable_hsts", "enable_hsts_subdomains", "disable_http",
                            "upgrade_tls", "add_csp", "add_x_content_type_options",
                            "add_referrer_policy", "set_cookie_secure", "set_cookie_httponly"]
            all_ops = [(f, op) for f in fallback_fields for op in fallback_ops]
            logger.warning("Ontology empty, using fallback operation space.")
        return all_ops

    # ---------- Chromosome representation ----------
    def _random_chromosome(self) -> Tuple[List[Tuple[str, str]], float]:
        """Generate a random chromosome with a random mutation rate."""
        # Normalizers: random subset of operations (size 0 to 4)
        size = random.randint(0, min(4, len(self.ALL_POSSIBLE)))
        norm_set = random.sample(self.ALL_POSSIBLE, min(size, len(self.ALL_POSSIBLE)))
        # Mutation rate: random between 0.05 and 0.95
        rate = random.uniform(0.05, 0.95)
        return (norm_set, rate)

    def _normalizers(self, chromosome: Tuple) -> List[Tuple[str, str]]:
        return chromosome[0]

    def _rate(self, chromosome: Tuple) -> float:
        return chromosome[1]

    # ---------- Fitness (counts total passes) ----------
    def _fitness(self, chromosome: Tuple[List[Tuple[str, str]], float]) -> int:
        norm_set = self._normalizers(chromosome)

        # Cache by normalizers only (rate doesn't affect fitness)
        key = tuple(sorted(norm_set))
        if key in self._cache:
            return self._cache[key]

        # Clear and register normalizers
        if hasattr(self.validator, "clear_normalizers"):
            self.validator.clear_normalizers()
        for field, op in norm_set:
            suggestion = {"field": field, "operation": op}
            normalizer = self.rules.create_normalizer_from_suggestion(suggestion)
            if normalizer and hasattr(self.validator, "register_normalizer"):
                self.validator.register_normalizer(normalizer)

        # Load records and validate
        with open(self.input_path) as f:
            records = json.load(f)

        total_passes = 0
        expected_checks = getattr(self.validator, "EXPECTED_CHECKS", 5)
        for rec in records:
            valid, errors = self.validator.validate_record(rec)
            passes = max(0, expected_checks - len(errors))
            total_passes += passes

        self._cache[key] = total_passes
        return total_passes

    # ---------- Genetic operators ----------
    def _crossover(
        self, parent1: Tuple, parent2: Tuple
    ) -> Tuple[Tuple[List[Tuple[str, str]], float], Tuple[List[Tuple[str, str]], float]]:
        # 1. Crossover normalizers (same as before)
        p1_set = set(self._normalizers(parent1))
        p2_set = set(self._normalizers(parent2))
        common = p1_set.intersection(p2_set)
        u1 = list(p1_set - common)
        u2 = list(p2_set - common)
        random.shuffle(u1)
        random.shuffle(u2)
        split1 = len(u1) // 2
        split2 = len(u2) // 2
        child1_norm = list(common) + u1[:split1] + u2[:split2]
        child2_norm = list(common) + u1[split1:] + u2[split2:]
        child1_norm = list(dict.fromkeys(child1_norm))
        child2_norm = list(dict.fromkeys(child2_norm))

        # 2. Blend mutation rates (average, with small random deviation)
        rate1 = (self._rate(parent1) + self._rate(parent2)) / 2.0
        rate2 = rate1 * (1.0 + random.uniform(-0.1, 0.1))  # slight variation
        rate1 = max(0.05, min(0.95, rate1))
        rate2 = max(0.05, min(0.95, rate2))

        return (child1_norm, rate1), (child2_norm, rate2)

    def _mutate(self, chromosome: Tuple) -> Tuple:
        norm_set = self._normalizers(chromosome)
        rate = self._rate(chromosome)

        new_norm = norm_set[:]
        # Mutate normalizers using the chromosome's own rate
        if random.random() < rate:
            action = random.choice(["add", "remove", "replace"])
            if action == "add" and len(new_norm) < len(self.ALL_POSSIBLE):
                available = [item for item in self.ALL_POSSIBLE if item not in set(new_norm)]
                if available:
                    new_norm.append(random.choice(available))
            elif action == "remove" and new_norm:
                idx = random.randint(0, len(new_norm) - 1)
                new_norm.pop(idx)
            elif action == "replace" and new_norm:
                idx = random.randint(0, len(new_norm) - 1)
                old = new_norm.pop(idx)
                available = [item for item in self.ALL_POSSIBLE if item not in set(new_norm)]
                if available:
                    new_norm.append(random.choice(available))
                else:
                    new_norm.insert(idx, old)

        # Mutate the mutation rate itself (multiplicative, clamped)
        if random.random() < 0.1:  # rate mutation probability (can also be self-adapted)
            rate *= random.uniform(0.8, 1.2)
            rate = max(0.05, min(0.95, rate))

        return (new_norm, rate)

    # ---------- Seeding ----------
    def _seed_from_learning_store(self) -> List[Tuple]:
        seeds = []
        failures = load_learning_failures()
        if not failures:
            return seeds

        suggestions = self.rules.suggest_improvements(failures)
        if not suggestions:
            return seeds

        # Combined
        combined = [(s["field"], s["operation"]) for s in suggestions]
        if combined:
            seeds.append((combined, self.initial_mutation_rate))

        # Each individually
        for s in suggestions:
            seeds.append(([(s["field"], s["operation"])], self.initial_mutation_rate))

        # Random subsets
        for _ in range(3):
            if len(suggestions) > 1:
                subset = random.sample(suggestions, random.randint(1, len(suggestions)))
                chrom = [(s["field"], s["operation"]) for s in subset]
                seeds.append((chrom, self.initial_mutation_rate))

        return seeds

    # ---------- Permanent application ----------
    def _apply_permanently(self, chromosome: Tuple) -> None:
        norm_set = self._normalizers(chromosome)
        for field, op in norm_set:
            suggestion = {"field": field, "operation": op}
            add_normalizer_to_code(suggestion)
        reload_dynamic_normalizers()
        logger.info(f"✅ Permanently applied {len(norm_set)} normalizers to code.")

    # ---------- Main evolution loop ----------
    def run(self):
        logger.info("🧬 Starting Evolutionary Agent (self‑adaptive mutation rate)...")

        # Compute max possible fitness
        with open(self.input_path) as f:
            records = json.load(f)
        expected_checks = getattr(self.validator, "EXPECTED_CHECKS", 5)
        self.max_possible = len(records) * expected_checks
        logger.info(f"Max possible fitness: {self.max_possible}")

        # 1. Baseline (empty chromosome with default rate)
        empty_chrom = ([], self.initial_mutation_rate)
        baseline = self._fitness(empty_chrom)
        logger.info(f"Baseline fitness (no normalizers): {baseline}")

        # 2. Seed population
        population = []
        if self.use_learning_store:
            seeds = self._seed_from_learning_store()
            logger.info(f"Seeded {len(seeds)} chromosomes from learning store.")
            population.extend(seeds)

        while len(population) < self.population_size - 1:
            population.append(self._random_chromosome())
        # Ensure we have at least the empty chromosome as a baseline
        if empty_chrom not in population:
            population.append(empty_chrom)

        # 3. Evaluate initial fitness
        fitnesses = []
        for chrom in population:
            fit = self._fitness(chrom)
            fitnesses.append(fit)
            if fit > self.best_fitness:
                self.best_fitness = fit
                self.best_ever = chrom
                logger.info(f"🏆 New best fitness: {fit} (normalizers: {len(self._normalizers(chrom))}, rate: {self._rate(chrom):.3f})")

        if self.best_fitness == self.max_possible:
            logger.info("🎉 Already perfect! No evolution needed.")
            return self.best_ever

        # 4. Evolution loop
        for gen in range(self.generations):
            logger.info(f"--- Generation {gen+1}/{self.generations} ---")

            # Selection (tournament)
            new_population = []
            for _ in range(self.population_size):
                a = random.randint(0, self.population_size - 1)
                b = random.randint(0, self.population_size - 1)
                winner = population[a] if fitnesses[a] >= fitnesses[b] else population[b]
                new_population.append(winner)

            # Elitism
            sorted_idx = sorted(range(self.population_size), key=lambda i: fitnesses[i], reverse=True)
            elite = [population[i] for i in sorted_idx[:self.elite_size]]
            new_population[:self.elite_size] = elite

            # Crossover (only on non‑elite)
            for i in range(self.elite_size, self.population_size - 1, 2):
                p1 = new_population[i]
                p2 = new_population[i + 1]
                c1, c2 = self._crossover(p1, p2)
                new_population[i] = c1
                new_population[i + 1] = c2

            # Mutation (on non‑elite)
            for i in range(self.elite_size, self.population_size):
                new_population[i] = self._mutate(new_population[i])

            # Evaluate
            population = new_population
            fitnesses = [self._fitness(chrom) for chrom in population]
            gen_best = max(fitnesses)
            if gen_best > self.best_fitness:
                self.best_fitness = gen_best
                self.best_ever = population[fitnesses.index(gen_best)]
                logger.info(f"🏆 New best fitness: {self.best_fitness} (normalizers: {len(self._normalizers(self.best_ever))}, rate: {self._rate(self.best_ever):.3f})")

            if self.best_fitness == self.max_possible:
                logger.info("🎉 Perfect solution found! Stopping early.")
                break

        logger.info(f"✅ Evolution finished. Best fitness: {self.best_fitness}")

        if self.permanent and self.best_ever and self.best_fitness > 0:
            self._apply_permanently(self.best_ever)
        elif self.permanent and self.best_ever and self.best_fitness == 0:
            logger.info("No improvement – skipping permanent application.")

        return self.best_ever