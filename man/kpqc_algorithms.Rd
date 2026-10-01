\name{kpqc_algorithms}
\alias{aimer128f}
\alias{aimer128s}
\alias{aimer192f}
\alias{aimer192s}
\alias{aimer256f}
\alias{aimer256s}
\alias{haetae2}
\alias{haetae3}
\alias{haetae5}
\alias{ntruplus768}
\alias{ntruplus864}
\alias{ntruplus1152}
\alias{smaugt128}
\alias{smaugt192}
\alias{smaugt256}
\alias{timer}
\alias{signature_algorithms}
\alias{kem_algorithms}
\title{KpqC Algorithms}
\usage{
aimer128f()
aimer128s()
aimer192f()
aimer192s()
aimer256f()
aimer256s()
haetae2()
haetae3()
haetae5()
ntruplus768()
ntruplus864()
ntruplus1152()
smaugt128()
smaugt192()
smaugt256()
timer()
signature_algorithms()
kem_algorithms()
}
\description{
Construct algorithm descriptors for every supported KpqC parameter set.
}
\value{
An accessor returns a \code{kpqc_algorithm} object containing the algorithm
identifier, type, and byte sizes. The collection functions return lists of
all signature or key-encapsulation algorithms.
}
\examples{
algorithm <- aimer128f()
algorithm$id
algorithm$sizes

length(signature_algorithms())
length(kem_algorithms())
}
