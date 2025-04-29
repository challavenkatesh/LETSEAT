export default function HeroBackground() {
    return (
      <div className="relative h-screen w-full flex items-center justify-center bg-black overflow-hidden">
        {/* Animated Gradient Background */}
        <div className="absolute inset-0 bg-gradient-to-br from-red-700 via-black to-white animate-pulse-slow"></div>
  
        {/* Centered Glass Effect Card */}
        <div className="relative z-10 bg-white/10 backdrop-blur-md p-12 rounded-xl border border-white/20 shadow-2xl">
          <h1 className="text-white text-6xl font-bold tracking-wide glow-text">
            Elevate Your Experience
          </h1>
        </div>
  
        {/* Subtle Moving Abstract Lines */}
        <div className="absolute inset-0">
          <div className="absolute w-full h-full bg-grid opacity-10 animate-fade"></div>
        </div>
  
        <style>
          {`
            @keyframes fade {
              0% { opacity: 0.2; }
              50% { opacity: 0.5; }
              100% { opacity: 0.2; }
            }
            
            @keyframes pulse-slow {
              0% { background-size: 200% 200%; }
              50% { background-size: 250% 250%; }
              100% { background-size: 200% 200%; }
            }
  
            .animate-pulse-slow {
              animation: pulse-slow 10s ease infinite;
            }
  
            .glow-text {
              text-shadow: 0 0 20px rgba(255, 0, 0, 0.8), 0 0 40px rgba(255, 0, 0, 0.6);
            }
  
            .bg-grid {
              background-image: linear-gradient(rgba(255, 255, 255, 0.1) 1px, transparent 1px),
                                linear-gradient(90deg, rgba(255, 255, 255, 0.1) 1px, transparent 1px);
              background-size: 50px 50px;
            }
          `}
        </style>
      </div>
    );
  }
  