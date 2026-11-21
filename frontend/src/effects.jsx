import { createRoot } from "react-dom/client";
import SpotlightCard from "@/components/react-bits/SpotlightCard";

const title = document.getElementById("page-title");
const demo = document.getElementById("demo-input");
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const finePointer = window.matchMedia("(any-hover: hover) and (any-pointer: fine)");

if (!reduceMotion.matches) {
  import("@/components/react-bits/SplitText").then(({ default: SplitText }) => {
    createRoot(title).render(
      <SplitText
        text={title.textContent}
        tag="span"
        splitType="words"
        from={{ opacity: 0, y: 4 }}
        to={{ opacity: 1, y: 0 }}
        duration={0.17}
        delay={25}
        trigger="load"
        textAlign="left"
      />,
    );
  }).catch(() => {
    // The original heading remains available if the animation can't load.
  });
}

if (finePointer.matches && !reduceMotion.matches) {
  const [heading, description] = [...demo.children].map((element) => element.textContent);
  createRoot(demo).render(
    <SpotlightCard
      className="demo-spotlight"
      spotlightColor="var(--accent)"
      intensity={0.13}
      spotlightSize={170}
      borderGlow={0.18}
      proximity={0}
      flare={false}
      style={{
        "--spotlight-card-surface": "transparent",
        "--spotlight-card-border": "transparent",
        "--spotlight-card-shadow": "none",
      }}
    >
      <strong>{heading}</strong>
      <p>{description}</p>
    </SpotlightCard>,
  );
}
