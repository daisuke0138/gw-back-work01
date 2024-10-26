-- CreateTable
CREATE TABLE "Imagelist" (
    "id" SERIAL NOT NULL,
    "kinds" TEXT NOT NULL,
    "imageName" TEXT NOT NULL,
    "imageUrl" TEXT NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Imagelist_pkey" PRIMARY KEY ("id")
);
